//! HTTP Server that returns TLSNotary proofs for Binance BTC/USDT price
//!
//! This server:
//! 1. Receives HTTP GET requests
//! 2. Generates a fresh TLSNotary proof from Binance
//! 3. Returns JSON with the presentation (proof) and verification result
//!
//! Usage:
//!   cargo run --example binance_oracle_server
//!
//! Then in another terminal:
//!   curl http://localhost:3000/price

use std::env;

use http_body_util::{Empty, Full};
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use tlsn_core::hash::{HashAlgId, HashAlgorithm, Sha256};
use tlsn_core::signing::{Secp256k1EthVerifier, SignatureAlgId};
use tokio::net::TcpListener;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::error;

use notary_client::{Accepted, NotarizationRequest, NotaryClient};
use tlsn_common::config::ProtocolConfig;
use tlsn_core::{
    request::RequestConfig,
    transcript::{TranscriptCommitConfig, TranscriptCommitmentKind},
    CryptoProvider,
};
use tlsn_prover::{Prover, ProverConfig};

const API_HOST: &str = "api.binance.com";
const API_PATH: &str = "/api/v3/ticker/price?symbol=BTCUSDT";
const MAX_SENT: usize = 1024;
const MAX_RECV: usize = 4096;

const PSE_NOTARY_HOST: &str = "notary.pse.dev";
const PSE_NOTARY_PORT: u16 = 7047;

#[derive(Debug, Deserialize, Serialize)]
struct BinancePrice {
    symbol: String,
    price: String,
}

/// Response returned by the server
#[derive(Debug, Serialize)]
struct OracleResponse {
    /// The TLSNotary presentation as base64-encoded bincode (for Noir)
    presentation_bincode: String,
    /// The TLSNotary presentation as JSON (for easy parsing in TypeScript)
    presentation_json: serde_json::Value,
    /// Verification result
    verification: VerificationResult,
    /// The serialized header of the attestation
    header_serialized: Vec<u8>,
    /// Field hashes in merkle tree order
    field_hashes: Vec<Vec<u8>>,
    /// Hash commitment proof for on-chain verification
    hash_proof: HashProofData,
    /// Merkle proof showing committed_hash is in header.root
    body_merkle_proof: BodyMerkleProof,
}

/// Merkle proof that committed_hash is in the signed header
#[derive(Debug, Serialize)]
struct BodyMerkleProof {
    /// Merkle root (from header)
    root: Vec<u8>,
    /// Index of committed_hash in field_hashes
    leaf_index: usize,
    /// Merkle proof hashes (sibling hashes along the path)
    /// NOTE: This will be minimal/empty because attestation proves ALL fields.
    /// For gas-efficient on-chain verification of a single field, use all_field_hashes
    /// to reconstruct the Merkle tree off-chain.
    proof_hashes: Vec<Vec<u8>>,
    /// Total number of leaves in the tree
    leaf_count: usize,
    /// All field hashes in the Merkle tree (for off-chain verification)
    /// This allows verifiers to reconstruct the full tree and generate
    /// a single-field proof if needed for gas optimization.
    all_field_hashes: Vec<Vec<u8>>,
}

/// Hash commitment proof data for on-chain verification
#[derive(Debug, Serialize)]
struct HashProofData {
    /// Hash algorithm used (1 = SHA256)
    hash_algorithm: u8,
    /// The committed hash: hash(plaintext || blinder)
    committed_hash: Vec<u8>,
    /// The FULL committed plaintext (entire HTTP response)
    /// Extract the price using plaintext[price_range]
    plaintext: String,
    /// Byte range of the price within the plaintext
    price_range: std::ops::Range<usize>,
    /// The blinder used in the hash
    blinder: Vec<u8>,
    /// Direction (Sent or Received)
    direction: String,
}

#[derive(Debug, Serialize)]
struct VerificationResult {
    verified: bool,
    server: String,
    timestamp: String,
    symbol: String,
    price: String,
    notary_pubkey: String,
    signature_algorithm: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let addr = "127.0.0.1:3000";
    let listener = TcpListener::bind(addr).await?;

    println!("\n🚀 Binance TLSNotary Oracle Server");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    println!("🌐 Listening on: http://{}", addr);
    println!("📡 Endpoint: GET /price");
    println!();
    println!("Try: curl http://{}/price", addr);
    println!();

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);

        tokio::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(io, service_fn(handle_request))
                .await
            {
                error!("Error serving connection: {:?}", err);
            }
        });
    }
}

async fn handle_request(
    req: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if req.uri().path() == "/price" && req.method() == hyper::Method::GET {
        println!("📥 Received request for price");

        match generate_oracle_proof().await {
            Ok(response) => {
                let json = serde_json::to_string_pretty(&response).unwrap();
                println!("✅ Returning proof and verification");

                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "application/json")
                    .body(Full::new(Bytes::from(json)))
                    .unwrap())
            }
            Err(e) => {
                error!("❌ Error generating proof: {}", e);

                let error_response = serde_json::json!({
                    "error": format!("{}", e)
                });

                Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .header("Content-Type", "application/json")
                    .body(Full::new(Bytes::from(error_response.to_string())))
                    .unwrap())
            }
        }
    } else {
        Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from("Not Found")))
            .unwrap())
    }
}

/// Generate a TLSNotary proof and return presentation + verification
async fn generate_oracle_proof() -> Result<OracleResponse, Box<dyn std::error::Error>> {
    // Check for local notary override
    let use_local = env::var("USE_LOCAL_NOTARY").is_ok();
    let (notary_host, notary_port, use_tls) = if use_local {
        println!("Using local notary");
        ("127.0.0.1".to_string(), 7047, false)
    } else {
        println!("Using PSE public notary");
        (PSE_NOTARY_HOST.to_string(), PSE_NOTARY_PORT, true)
    };

    // CryptoProvider already includes SHA256 by default
    let mut crypto_provider = CryptoProvider::default();
    crypto_provider
        .signature
        .set_verifier(Box::new(Secp256k1EthVerifier));

    let mut crypto_provider1 = CryptoProvider::default();
    crypto_provider1
        .signature
        .set_verifier(Box::new(Secp256k1EthVerifier));

    let mut crypto_provider2 = CryptoProvider::default();
    crypto_provider2
        .signature
        .set_verifier(Box::new(Secp256k1EthVerifier));

    // Connect to Notary
    let notary_client = NotaryClient::builder()
        .host(&notary_host)
        .port(notary_port)
        .enable_tls(use_tls)
        .build()?;

    let notarization_request = NotarizationRequest::builder()
        .max_sent_data(MAX_SENT)
        .max_recv_data(MAX_RECV)
        .build()?;

    let Accepted {
        io: notary_connection,
        id: session_id,
        ..
    } = notary_client
        .request_notarization(notarization_request)
        .await
        .map_err(|e| format!("Notary connection failed: {}. Try: USE_LOCAL_NOTARY=1", e))?;

    println!("Notary session: {}", session_id);

    // Configure Prover
    let prover_config = ProverConfig::builder()
        .server_name(API_HOST)
        .protocol_config(
            ProtocolConfig::builder()
                .max_sent_data(MAX_SENT)
                .max_recv_data(MAX_RECV)
                .build()?,
        )
        .crypto_provider(crypto_provider)
        .build()?;

    // Setup MPC with Notary
    let prover = Prover::new(prover_config)
        .setup(notary_connection.compat())
        .await?;

    // Connect to Binance
    let client_socket = tokio::net::TcpStream::connect((API_HOST, 443)).await?;
    let (mpc_tls_connection, prover_fut) = prover.connect(client_socket.compat()).await?;
    let mpc_tls_connection = TokioIo::new(mpc_tls_connection.compat());
    let prover_task = tokio::spawn(prover_fut);

    // Make HTTP request
    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(mpc_tls_connection).await?;
    tokio::spawn(connection);

    let request = hyper::Request::builder()
        .uri(API_PATH)
        .header("Host", API_HOST)
        .header("Accept", "application/json")
        .header("Connection", "close")
        .body(Empty::<Bytes>::new())?;

    let response = request_sender.send_request(request).await?;

    if response.status() != StatusCode::OK {
        return Err(format!("API error: {}", response.status()).into());
    }

    // Wait for prover
    let mut prover = prover_task.await??;

    // Parse response
    let body_str = std::str::from_utf8(prover.transcript().received())?;
    let json_start = body_str.rfind('{').ok_or("No JSON found")?;
    let json_str = &body_str[json_start..];
    let price_data: BinancePrice = serde_json::from_str(json_str)?;

    println!("Price: {} {}", price_data.price, price_data.symbol);

    // Find the price value in the JSON response
    let price_key = "\"price\":\"";
    let price_start_idx = json_str.find(price_key)
        .ok_or("Price key not found in JSON")?
        + price_key.len();
    let price_end_idx = json_str[price_start_idx..].find('"')
        .ok_or("Price value end quote not found")?
        + price_start_idx;

    // Calculate absolute positions in the received data
    let price_abs_start = json_start + price_start_idx;
    let price_abs_end = json_start + price_end_idx;
    let price_range = price_abs_start..price_abs_end;

    println!("Price location: bytes {}-{} in received data", price_abs_start, price_abs_end);
    println!("Price value: {}", &json_str[price_start_idx..price_end_idx]);

    // Commit to transcript using HASH commitments (raw plaintext)
    // Only commit to received data (the Binance API response with the price)
    // Hash commitments directly hash: hash(plaintext || blinder)
    let (_sent_len, recv_len) = prover.transcript().len();

    let transcript_commit = {
        let mut builder = TranscriptCommitConfig::builder(prover.transcript());

        // Only commit to received data with hash commitment
        builder.commit_with_kind(
            &(0..recv_len),
            tlsn_core::transcript::Direction::Received,
            TranscriptCommitmentKind::Hash {
                alg: HashAlgId::SHA256,
            },
        )?;
        builder.build()?
    };

    // Request attestation
    let mut req_builder = RequestConfig::builder();
    req_builder.hash_alg(HashAlgId::SHA256);
    req_builder.signature_alg(SignatureAlgId::SECP256K1ETH);
    req_builder.transcript_commit(transcript_commit);
    let request_config = req_builder.build()?;

    #[allow(deprecated)]
    let (attestation, secrets) = prover.notarize(&request_config).await?;
    prover.close().await?;

    // Build presentation - reveal the entire received data
    // Note: Hash commitments don't support selective revelation like encoding commitments do
    // So we must reveal the entire committed range (full received transcript)
    let mut transcript_builder = secrets.transcript_proof_builder();
    transcript_builder
        .reveal(&(0..recv_len), tlsn_core::transcript::Direction::Received)?;
    let transcript_proof = transcript_builder.build()?;

    let mut pres_builder = attestation.presentation_builder(&crypto_provider1);
    pres_builder
        .identity_proof(secrets.identity_proof())
        .transcript_proof(transcript_proof);
    let presentation = pres_builder.build()?;

    // Verify the presentation to extract verified data
    let output = presentation.clone().verify(&crypto_provider2)?;

    let notary_pubkey = hex::encode(&presentation.verifying_key().data);
    let server = output
        .server_name
        .map(|s| s.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let timestamp =
        chrono::DateTime::UNIX_EPOCH + std::time::Duration::from_secs(output.connection_info.time);

    // Extract hash commitment data from the presentation
    // Hash commitments are simpler: just hash(plaintext || blinder)
    // No Merkle tree needed!

    let transcript_proof_ref = presentation
        .transcript_proof()
        .ok_or("No transcript proof found in presentation")?;

    let hash_secrets = transcript_proof_ref.hash_secrets();

    // Find the hash secret for the price range
    let price_hash_secret = hash_secrets
        .iter()
        .find(|secret| {
            secret.direction == tlsn_core::transcript::Direction::Received
                && secret.idx.iter_ranges().any(|r| {
                    r.start <= price_range.start && r.end >= price_range.end
                })
        })
        .ok_or("No hash secret found for price range")?;

    // Get the plaintext from the partial transcript
    let partial_transcript = transcript_proof_ref.partial_transcript();

    // The committed hash is hash(plaintext || blinder)
    // We can reconstruct it from the secret directly
    let crypto_provider_for_hash = CryptoProvider::default();
    let hasher = crypto_provider_for_hash
        .hash
        .get(&price_hash_secret.alg)
        .map_err(|e| format!("Hash algorithm not found: {}", e))?;

    // Extract the plaintext data corresponding to the price hash secret's index
    let mut plaintext_data = Vec::new();
    for range in price_hash_secret.idx.iter_ranges() {
        plaintext_data.extend_from_slice(&partial_transcript.received_unsafe()[range]);
    }

    // Compute the committed hash: SHA256(plaintext || blinder)
    let committed_hash_typed = tlsn_core::transcript::hash::hash_plaintext(
        hasher,
        &plaintext_data,
        &price_hash_secret.blinder
    );
    let committed_hash_raw = committed_hash_typed.value.value[..committed_hash_typed.value.len].to_vec();

    // Convert the full committed plaintext to UTF-8 string
    let full_plaintext_str = match std::str::from_utf8(&plaintext_data) {
        Ok(s) => s.to_string(),
        Err(_) => {
            hex::encode(&plaintext_data)
        }
    };

    let hash_proof_data = HashProofData {
        hash_algorithm: 1, // SHA256
        committed_hash: committed_hash_raw,
        plaintext: full_plaintext_str, // FULL HTTP response, not just price!
        price_range: price_range.clone(),
        blinder: price_hash_secret.blinder.as_bytes().to_vec(),
        direction: "Received".to_string(),
    };

    // Serialize presentation to bincode (base64) for Noir
    let presentation_bytes = bincode::serialize(&presentation)?;
    let presentation_bincode = base64::encode(&presentation_bytes);

    // Serialize presentation to JSON for TypeScript
    let presentation_json = serde_json::to_value(&presentation)?;

    // Get signature algorithm name
    let sig_alg = match attestation.signature.alg {
        SignatureAlgId::SECP256K1 => "secp256k1",
        SignatureAlgId::SECP256R1 => "secp256r1",
        SignatureAlgId::SECP256K1ETH => "secp256k1eth",
        _ => "unknown",
    };

    // Compute field hashes in merkle tree order
    let hasher = Sha256::default();
    let field_hashes_with_kind: Vec<_> = attestation.body.hash_fields(&hasher);
    let field_hashes: Vec<Vec<u8>> = field_hashes_with_kind
        .iter()
        .map(|(_, hash)| hash.value[..hash.len].to_vec())  // Only include actual hash bytes, not padding
        .collect();

    // Get the body Merkle proof from the attestation
    // The presentation already contains a Merkle proof showing all body fields are in header.root
    let attestation_proof = presentation.attestation_proof();

    // The transcript commitment is the 5th field (index 4) after:
    // verifying_key, connection_info, server_ephemeral_key, cert_commitment
    // Note: The field hash is hash_separated(PlaintextHash), not the raw committed_hash
    let committed_hash_field_index = 4;

    println!("  - Committed hash is at field index: {}", committed_hash_field_index);

    // Extract Merkle proof from attestation
    // NOTE: The attestation proof proves ALL fields at once (indices 0-4).
    // For gas-efficient on-chain verification, you would ideally create a proof
    // for just the transcript commitment field (index 4).
    // Since we can't create single-field proofs here (MerkleTree is private),
    // we provide all field hashes so verifiers can reconstruct the tree off-chain.
    let merkle_proof = attestation_proof.body_merkle_proof();

    let body_merkle_proof = BodyMerkleProof {
        root: attestation.header.root.value.value[..attestation.header.root.value.len].to_vec(),
        leaf_index: committed_hash_field_index,
        // proof_hashes will be minimal/empty because attestation proves ALL fields
        // For a single-field proof, these would contain sibling hashes along the path
        proof_hashes: merkle_proof
            .proof_hashes()
            .iter()
            .map(|h| h.value[..h.len].to_vec())  // Only include actual hash bytes
            .collect(),
        leaf_count: field_hashes_with_kind.len(),
        // Include ALL field hashes so verifier can reconstruct the tree if needed
        all_field_hashes: field_hashes_with_kind
            .iter()
            .map(|(_, hash)| hash.value[..hash.len].to_vec())  // Only include actual hash bytes
            .collect(),
    };

    println!("✅ Body Merkle proof extracted:");
    println!("  - Root (from header): {}", hex::encode(&body_merkle_proof.root));
    println!("  - Leaf index: {}", body_merkle_proof.leaf_index);
    println!("  - Proof hashes: {}", body_merkle_proof.proof_hashes.len());
    println!("  - Total leaves: {}", body_merkle_proof.leaf_count);

    println!("\n✅ Hash commitment proof extracted:");
    println!("  - Committed hash: {}", hex::encode(&hash_proof_data.committed_hash));
    println!("  - Plaintext price: {}", hash_proof_data.plaintext);
    println!("  - Blinder: {}", hex::encode(&hash_proof_data.blinder));
    println!("  - Algorithm: SHA256");

    // Manually verify the hash commitment to demonstrate the process
    println!("\n🔍 Manual verification of hash commitment:");

    // Step 1: Concatenate FULL committed plaintext || blinder
    // IMPORTANT: The hash is computed over the ENTIRE committed range, not just the price!
    let mut preimage = Vec::new();
    preimage.extend_from_slice(&plaintext_data); // Use the full committed plaintext, not just the price!
    preimage.extend_from_slice(&hash_proof_data.blinder);

    println!("  Step 1: Concatenate plaintext || blinder");
    println!("    - Full committed plaintext length: {} bytes", plaintext_data.len());
    println!("    - Price value: {}", hash_proof_data.plaintext);
    println!("    - Price location in committed data: bytes {}-{}", price_range.start, price_range.end);
    println!("    - Blinder: {}", hex::encode(&hash_proof_data.blinder));
    println!("    - Blinder length: {} bytes", hash_proof_data.blinder.len());
    println!("    - Total preimage length: {} bytes", preimage.len());

    // Step 2: Hash with SHA256
    let hasher = Sha256::default();
    let computed_hash = hasher.hash(&preimage); // Returns Hash struct

    println!("\n  Step 2: Hash with SHA256");
    println!("    - Input: {}", hex::encode(&preimage));
    println!("    - Computed hash: {}", hex::encode(&computed_hash.value[..computed_hash.len]));

    // Step 3: Compare with committed hash
    let matches = &computed_hash.value[..computed_hash.len] == hash_proof_data.committed_hash.as_slice();

    println!("\n  Step 3: Compare with committed hash");
    println!("    - Committed hash: {}", hex::encode(&hash_proof_data.committed_hash));
    println!("    - Computed hash:  {}", hex::encode(&computed_hash.value[..computed_hash.len]));
    println!("    - Match: {}", if matches { "✅ YES" } else { "❌ NO" });

    if !matches {
        return Err("Hash commitment verification failed!".into());
    }

    println!("\n✅ Hash commitment verified successfully!");

    // Now verify that this committed hash is in the Merkle tree signed by the notary
    println!("\n🔍 Verifying Merkle proof (committed hash is in signed header):");

    // The field_hashes list contains all the hashed fields from the attestation body
    // The transcript commitment field is at index committed_hash_field_index
    println!("  Step 1: Extract the transcript commitment field hash");
    println!("    - Field index in Merkle tree: {}", committed_hash_field_index);
    println!("    - Field hash: {}", hex::encode(&field_hashes[committed_hash_field_index]));
    println!("    - This is hash_separated(PlaintextHash), not the raw committed_hash");

    println!("\n  Step 2: Merkle tree structure");
    println!("    - Total fields in body: {}", field_hashes.len());
    println!("    - Merkle root (signed by notary): {}", hex::encode(&body_merkle_proof.root[..32]));
    println!("    - Number of Merkle proof hashes: {}", body_merkle_proof.proof_hashes.len());

    println!("\n  Step 3: Verification by presentation.verify()");
    println!("    - ✅ Notary signature on header: VERIFIED");
    println!("    - ✅ Merkle proof (field_hash → root): VERIFIED");
    println!("    - ✅ Hash opening (plaintext+blinder → committed_hash): VERIFIED");
    println!("\n  Note: presentation.verify() already performed these checks above");

    println!("\n✅ Complete verification chain:");
    println!("  1. ✅ Hash opening: SHA256(plaintext || blinder) = committed_hash");
    println!("  2. ✅ Field hash: hash_separated(PlaintextHash) is in attestation body");
    println!("  3. ✅ Merkle proof: field_hash is in header.root");
    println!("  4. ✅ Signature: Notary signed the header.root");
    println!("\n📝 For Noir verification, you need to:");
    println!("  1. Verify notary signature on header");
    println!("  2. Verify Merkle proof: field_hash is in header.root");
    println!("  3. Verify hash opening: SHA256(plaintext || blinder) = committed_hash");
    println!("  4. Extract price from plaintext at specified location");

    Ok(OracleResponse {
        presentation_bincode,
        presentation_json,
        verification: VerificationResult {
            verified: true,
            server,
            timestamp: timestamp.to_rfc3339(),
            symbol: price_data.symbol,
            price: price_data.price,
            notary_pubkey,
            signature_algorithm: sig_alg.to_string(),
        },
        header_serialized: bcs::to_bytes(&attestation.header).unwrap(),
        field_hashes,
        hash_proof: hash_proof_data,
        body_merkle_proof,
    })
}
