# Binance Oracle Server - Complete Guide

This guide explains how to run the TLSNotary Binance Oracle server and verify the cryptographic proofs it generates.

## Table of Contents

1. [Overview](#overview)
2. [Running the Notary Server Locally](#running-the-notary-server-locally)
3. [Running the Oracle Server](#running-the-oracle-server)
4. [Understanding the Response](#understanding-the-response)
5. [Verifying the Proof](#verifying-the-proof)
6. [Signature Algorithm Details](#signature-algorithm-details)

---

## Overview

The Binance Oracle Server generates TLSNotary proofs for the BTC/USDT price from Binance's API. Each request creates a fresh cryptographic proof that:

1. **Proves authenticity**: The price data came from Binance's server
2. **Proves integrity**: The data hasn't been tampered with
3. **Enables privacy**: You can selectively reveal parts of the transcript
4. **Supports ZK verification**: The proof can be verified in a Noir circuit

### Architecture

```
┌─────────────────┐
│  Oracle Server  │  (generates proofs)
└────────┬────────┘
         │
    ┌────┴─────────────────────┐
    │                           │
    ▼                           ▼
┌─────────┐              ┌──────────┐
│ Binance │              │  Notary  │
│   API   │◄────MPC─────►│  Server  │
└─────────┘              └──────────┘
                              │
                              ▼
                         Signs proof
                       (SECP256K1ETH)
```

---

## Running the Notary Server Locally

The Notary server acts as a trusted third party that co-signs the TLS session.

### Step 1: Build the Notary Server

```bash
# From the tlsn repository root
cargo build --bin notary-server --release
```

### Step 2: Start the Notary with SECP256K1ETH Signature

This oracle uses **SECP256K1ETH** signatures (ECDSA with Keccak-256 hashing):

```bash
NS_NOTARIZATION__SIGNATURE_ALGORITHM=secp256k1eth \
    target/release/notary-server
```

You should see:

```
⚠️ Using a random, ephemeral signing key because `notarization.private_key_path` is not set.
Listening on 0.0.0.0:7047
```

**Why SECP256K1ETH?**
- Uses **Keccak-256** hashing (more SNARK-friendly than SHA-256)
- **Ethereum-compatible** signature format (same as `ecrecover`)
- Optimized for **Noir circuits** - significantly more efficient to verify in ZK
- 65-byte signatures include recovery ID (`r || s || v`)

### Step 3: Keep It Running

Leave this terminal open. The notary server must be running when you make oracle requests.

### Optional: Using a Persistent Key

For production, you should use a persistent signing key:

```bash
# Generate a key
openssl ecparam -name secp256k1 -genkey -noout -out notary_key.pem

# Start notary with the key
NS_NOTARIZATION__PRIVATE_KEY_PATH=./notary_key.pem \
    target/release/notary-server
```

---

## Running the Oracle Server

### Step 1: Build the Oracle Server

```bash
cargo build --example binance_oracle_server --release
```

### Step 2: Start the Oracle Server

```bash
USE_LOCAL_NOTARY=1 cargo run --example binance_oracle_server
```

You should see:

```
🚀 Binance TLSNotary Oracle Server
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🌐 Listening on: http://127.0.0.1:3000
📡 Endpoint: GET /price

Try: curl http://127.0.0.1:3000/price
```

### Step 3: Request a Proof

In another terminal:

```bash
curl http://localhost:3000/price | jq
```

**Note**: Each request takes **10-15 seconds** because it:
1. Connects to Binance via MPC-TLS
2. Performs the TLS handshake through the Notary
3. Makes the API request
4. Generates cryptographic commitments
5. Builds the presentation with Merkle proofs

---

## Understanding the Response

The server returns a JSON object with three main fields:

```json
{
  "presentation_json": { ... },       // Full cryptographic proof
  "verification": { ... },            // Pre-verified data
  "header_serialized": [...]          // BCS-serialized header (what the Notary signs)
}
```

### 1. `verification` - Quick Access to Verified Data

```json
{
  "verified": true,
  "server": "api.binance.com",
  "timestamp": "2025-10-08T23:06:26+00:00",
  "symbol": "BTCUSDT",
  "price": "123104.96000000",
  "notary_pubkey": "03c15beda85f876eb8b8be8586a4175cc0ae6080bca3df935ba690f4d4fac2fff2",
  "signature_algorithm": "secp256k1eth"
}
```

- `verified`: The server already verified the proof
- `server`: The API server that was queried
- `timestamp`: When the TLS connection was established
- `symbol`: The trading pair
- `price`: The current price
- `notary_pubkey`: The Notary's public key (33 bytes, compressed, hex-encoded)
- `signature_algorithm`: Always `"secp256k1eth"` for this oracle

### 2. `presentation_json` - Complete Cryptographic Proof

This contains the complete cryptographic proof:

```json
{
  "attestation": {
    "signature": {
      "alg": 3,              // 3 = SECP256K1ETH
      "data": [...]          // 65 bytes: r || s || v
    },
    "header": {
      "id": [...],           // 16 bytes - unique attestation ID
      "version": 0,
      "root": {
        "alg": 2,            // 2 = Blake3
        "value": [...]       // 32 bytes - Merkle root of body
      }
    },
    "body": {
      "verifying_key": {...},         // Notary's public key
      "connection_info": {...},       // Timestamp, TLS version
      "server_ephemeral_key": {...},  // Server's ephemeral key
      "transcript_commitments": [...] // Merkle commitments to HTTP data
    }
  },
  "identity": {
    "name": "api.binance.com",
    "opening": {
      "data": {
        "certs": [...]       // DER-encoded TLS certificates
      }
    }
  },
  "transcript": {
    "transcript": {
      "sent_authed": [...],  // HTTP request bytes
      "received_authed": [...], // HTTP response bytes
      "sent_idx": [...],
      "recv_idx": [...]
    },
    "encoding_proof": {
      "openings": {...},     // Merkle proof openings
      "inclusion_proof": {...}
    }
  }
}
```

All data is in JSON format, making it easy to parse in TypeScript, Rust, or any language.

### 3. `header_serialized` - BCS-Serialized Header

The Header serialized using **BCS** (Binary Canonical Serialization):
- This is what the Notary signs
- Used to verify the signature
- Format: `id (17 bytes) || version (2 bytes) || root.alg (1 byte) || root.value (33 bytes)`

---

## Verifying the Proof

### Quick Access (Pre-verified)

The simplest approach - the server has already verified the cryptographic proof:

```typescript
const response = await fetch('http://localhost:3000/price');
const data = await response.json();

// Access verified data
console.log('Price:', data.verification.price);
console.log('Server:', data.verification.server);
console.log('Notary:', data.verification.notary_pubkey);
```

### Full Cryptographic Verification

For a complete example of how to verify the presentation and extract the price, see:

**[crates/examples/verify_presentation.rs](crates/examples/verify_presentation.rs)**

This example demonstrates:
- Loading and deserializing the presentation
- Verifying the Notary's signature (ECDSA with Keccak-256)
- Verifying all Merkle proofs
- Extracting the price from the authenticated HTTP response

Run it with:
```bash
cargo run --example verify_presentation
```

### Verification in Noir Circuit (ZK Proof)

The ultimate goal is to verify the proof in a Noir circuit for on-chain verification.

**High-level steps:**

1. **Decode the presentation from bincode**
2. **Verify the Notary's signature** (ECDSA with Keccak-256)
3. **Verify Merkle proofs** (Body → Header, Transcript → Body)
4. **Extract and validate the price**
5. **Generate a ZK proof** that all checks passed


For complete Noir implementation details, see:
- [NOIR_VERIFICATION_REQUIREMENTS.md](NOIR_VERIFICATION_REQUIREMENTS.md)
- [SIGNATURE_VERIFICATION_GUIDE.md](SIGNATURE_VERIFICATION_GUIDE.md)

---

## Signature Algorithm Details

This oracle uses **SECP256K1ETH** signatures exclusively:

**Signature Format:**
- **Algorithm**: ECDSA on secp256k1 curve
- **Hash Function**: Keccak-256 (Ethereum-compatible)
- **Signature Length**: 65 bytes
- **Format**: `r || s || v` where:
  - `r` (32 bytes): First part of ECDSA signature
  - `s` (32 bytes): Second part of ECDSA signature
  - `v` (1 byte): Recovery ID (27 or 28)

**Why This Matters:**
- The signature format is identical to Ethereum's `ecrecover`
- Keccak-256 is ~3x more efficient in Noir circuits than SHA-256
- The recovery ID (`v`) allows public key recovery (useful for some verification schemes)

**In the Response:**
```json
{
  "signature": {
    "alg": 3,              // 3 = SECP256K1ETH
    "data": [...]          // 65 bytes: [r(32), s(32), v(1)]
  }
}
```

---

## Troubleshooting

If not, start it:

```bash
NS_NOTARIZATION__SIGNATURE_ALGORITHM=secp256k1eth target/release/notary-server
```

### Error: "unexpected end of file"

**Solution**: The Notary and Oracle might be using incompatible configurations. Make sure:
1. The Notary server was started with `NS_NOTARIZATION__SIGNATURE_ALGORITHM=secp256k1eth`
2. Both servers are running
3. Restart both servers if needed

### Proof verification fails in Noir

**Check**:
1. Using Keccak-256 for hashing (not SHA-256) in your circuit
2. ECDSA signature verification is configured for secp256k1
3. BCS serialization of the header matches the expected format
4. Merkle proofs are properly constructed with Blake3 hashing

---

## Production Deployment

For production:

1. **Use a persistent Notary key**:
   ```bash
   openssl ecparam -name secp256k1 -genkey -noout -out notary_key.pem
   ```

2. **Enable TLS** on Notary server
3. **Configure rate limiting** on Oracle server
4. **Add authentication** (see notary server config)
5. **Cache presentations** to reduce proof generation
6. **Monitor the Notary** public key (log it on startup)

---

## Resources

- **TLSNotary Docs**: https://docs.tlsnotary.org
- **Noir Lang**: https://noir-lang.org
- **Source Code**: [crates/examples/binance_oracle_server.rs](crates/examples/binance_oracle_server.rs)
- **Example Verification**: [crates/examples/verify_presentation.rs](crates/examples/verify_presentation.rs)
