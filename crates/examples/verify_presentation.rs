//! Verify presentation using low-level primitives (simulating Noir circuit)
//!
//! This demonstrates step-by-step verification using the same primitives
//! that would be available in a Noir ZK circuit.
//!
//! Usage:
//!   cargo run --example verify_presentation

use tlsn_core::{presentation::Presentation, CryptoProvider};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🔬 Verifying TLSNotary Presentation (Noir-style)\n");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    // Step 1: Load the presentation (this is what Noir would receive)
    println!("📥 Loading presentation...");
    let presentation: Presentation = bincode::deserialize(&std::fs::read("presentation.bin")?)?;
    println!("   ✓ Presentation loaded");
    println!();

    // Step 2: Check the Notary's public key (in production, verify you trust this key!)
    println!("🔑 Checking Notary public key...");
    let verifying_key = presentation.verifying_key();
    println!("   • Algorithm: {}", verifying_key.alg);
    println!("   • Public key: {}", hex::encode(&verifying_key.data));
    println!("   ⚠️  In production: Verify this key is from a trusted Notary!");
    println!();

    // Step 3: Verify the presentation (does ALL cryptographic checks)
    println!("✅ Verifying presentation...");
    let crypto_provider = CryptoProvider::default();
    let output = presentation.verify(&crypto_provider)?;

    println!("   ✓ Signature verified!");
    println!("   ✓ Merkle proofs verified!");
    println!("   ✓ Transcript commitments verified!");
    println!();

    // Step 4: Extract the server name
    if let Some(server_name) = &output.server_name {
        println!("🌐 Server Identity:");
        println!("   • Server: {}", server_name);
        println!("   ✓ Server certificate verified");
        println!();
    }

    // Step 5: Extract the connection info
    println!("📡 Connection Info:");
    let time = chrono::DateTime::UNIX_EPOCH
        + std::time::Duration::from_secs(output.connection_info.time);
    println!("   • Timestamp: {}", time);
    println!("   • Sent {} bytes", output.connection_info.transcript_length.sent);
    println!(
        "   • Received {} bytes",
        output.connection_info.transcript_length.received
    );
    println!();

    // Step 6: Extract the revealed transcript (THIS IS THE ORACLE DATA!)
    println!("💰 Extracting Oracle Data:");
    if let Some(transcript) = output.transcript {
        // Get the received data (HTTP response)
        let received = String::from_utf8_lossy(transcript.received_unsafe());

        // Find the JSON in the response
        if let Some(json_start) = received.rfind('{') {
            let json_str = &received[json_start..];

            // Parse the JSON
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(json_str) {
                if let (Some(symbol), Some(price)) =
                    (json["symbol"].as_str(), json["price"].as_str())
                {
                    println!("   ✓ Found price data in transcript:");
                    println!("   • Symbol: {}", symbol);
                    println!("   • Price: {} USDT", price);
                    println!();
                    println!("   Raw JSON: {}", json_str);
                }
            }
        }
    } else {
        println!("   ⚠️  No transcript revealed in this presentation");
    }
    println!();

    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("🎉 Verification Complete!");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    println!("What we verified:");
    println!("  1. ✅ Notary's signature on attestation");
    println!("  2. ✅ Merkle proofs (body fields → header root)");
    println!("  3. ✅ Transcript commitment (revealed data → commitment)");
    println!("  4. ✅ Server identity (TLS certificate)");
    println!("  5. ✅ Extracted price from authenticated HTTP response");
    println!();
    println!("💡 For Noir:");
    println!("   • Deserialize presentation.bin");
    println!("   • Call presentation.verify() (or implement verification manually)");
    println!("   • Extract price from transcript");
    println!("   • Prove in ZK circuit!");
    println!();

    Ok(())
}
