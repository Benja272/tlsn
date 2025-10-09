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
use tlsn_core::hash::{HashAlgId, Keccak256};
use tlsn_core::signing::{Secp256k1EthVerifier, Secp256r1Signer, SignatureAlgId};
use tokio::net::TcpListener;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::{error, info};

use notary_client::{Accepted, NotarizationRequest, NotaryClient};
use tlsn_common::config::ProtocolConfig;
use tlsn_core::{
    presentation::Presentation, request::RequestConfig, transcript::TranscriptCommitConfig,
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
        info!("📥 Received request for price");

        match generate_oracle_proof().await {
            Ok(response) => {
                let json = serde_json::to_string_pretty(&response).unwrap();
                info!("✅ Returning proof and verification");

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
        info!("Using local notary");
        ("127.0.0.1".to_string(), 7047, false)
    } else {
        info!("Using PSE public notary");
        (PSE_NOTARY_HOST.to_string(), PSE_NOTARY_PORT, true)
    };

    let mut crypto_provider = CryptoProvider::default();
    crypto_provider
        .hash
        .set_algorithm(HashAlgId::KECCAK256, Box::new(Keccak256 {}));
    crypto_provider
        .signature
        .set_verifier(Box::new(Secp256k1EthVerifier));

    let mut crypto_provider1 = CryptoProvider::default();
    crypto_provider1
        .hash
        .set_algorithm(HashAlgId::KECCAK256, Box::new(Keccak256 {}));
    crypto_provider1
        .signature
        .set_verifier(Box::new(Secp256k1EthVerifier));

    let mut crypto_provider2 = CryptoProvider::default();
    crypto_provider2
        .hash
        .set_algorithm(HashAlgId::KECCAK256, Box::new(Keccak256 {}));
    crypto_provider2
        .signature
        .set_verifier(Box::new(Secp256k1EthVerifier));
    // No need to set a verifying key for the signer here; remove this line.

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

    info!("Notary session: {}", session_id);

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
    let json_str = body_str[json_start..].to_string();
    let price_data: BinancePrice = serde_json::from_str(&json_str)?;

    info!("Price: {} {}", price_data.price, price_data.symbol);

    // Commit to transcript
    let (sent_len, recv_len) = prover.transcript().len();

    let transcript_commit = {
        let mut builder = TranscriptCommitConfig::builder(prover.transcript());
        builder
            .commit_sent(&(0..sent_len))?
            .commit_recv(&(0..recv_len))?;
        builder.build()?
    };

    // Request attestation
    let mut req_builder = RequestConfig::builder();
    req_builder.hash_alg(HashAlgId::KECCAK256);
    req_builder.signature_alg(SignatureAlgId::SECP256K1ETH);
    req_builder.transcript_commit(transcript_commit);
    let request_config = req_builder.build()?;

    #[allow(deprecated)]
    let (attestation, secrets) = prover.notarize(&request_config).await?;
    prover.close().await?;

    // Build presentation
    let mut transcript_builder = secrets.transcript_proof_builder();
    transcript_builder
        .reveal(&(0..sent_len), tlsn_core::transcript::Direction::Sent)?
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
    })
}
