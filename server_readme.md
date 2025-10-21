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
NS_NOTARIZATION__SIGNATURE_ALGORITHM=secp256k1eth cargo run --release --bin notary-server
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

For a complete working example, see **[crates/examples/verify_presentation.rs](crates/examples/verify_presentation.rs)**

Run it with:
```bash
cargo run --example verify_presentation
```

---

## How Verification Works (Cryptographic Details)

This section explains the cryptographic verification process step-by-step, enabling implementation in any language or ZK circuit.

### The Verification Chain

```
Notary Signature
     ↓ (signs)
Header (contains header.root)
     ↓ (commits via Merkle)
Body (contains transcript_commitments[0])
     ↓ (commits via Merkle)
Transcript (HTTP request/response)
     ↓ (contains)
Price Data
```

Each level cryptographically commits to the next, creating an unbroken chain from signature to price.

### Step 1: Verify Notary's Signature

**What is signed:** Header structure (BCS-serialized)

**Algorithm:** ECDSA secp256k1 + Keccak-256

**Process:**

1. **Serialize Header with BCS**:
   - Length-prefix id: `[0x10] + id_bytes (16 bytes)`
   - Version as little-endian u16: `2 bytes`
   - Root.alg as u8: `1 byte`
   - Length-prefix root.value: `[0x20] + value_bytes (32 bytes)`
   - Total: ~53 bytes

2. **Hash with Keccak-256**:
   ```
   message_hash = Keccak256(header_bytes)  // 32 bytes
   ```

3. **Verify ECDSA**:
   ```
   ECDSA_verify(
     pubkey: notary_pubkey (33 bytes compressed),
     message: message_hash (32 bytes),
     signature: [r(32), s(32), v(1)]  // 65 bytes total
   )
   ```

**Why:** Proves Notary attested to this Header, which commits to all Body fields via `header.root`.

### Step 2: Verify Body Merkle Proof

**Goal:** Prove Body fields are in `header.root`

**Merkle tree fields:**
- Field 0: `verifying_key`
- Field 1: `connection_info`
- Field 2: `server_ephemeral_key`
- Field 3: `cert_commitment`
- Field 4: `transcript_commitments`

**Hash:** Blake3 (`header.root.alg = 2`)

**Process:**

1. **Hash each field**:
   ```
   leaf_i = Blake3(BCS_serialize(field_i))
   ```

2. **Build binary Merkle tree**:
   ```
   node_0_1 = Blake3(leaf_0 || leaf_1)
   node_2_3 = Blake3(leaf_2 || leaf_3)
   node_0_3 = Blake3(node_0_1 || node_2_3)
   root = Blake3(node_0_3 || leaf_4)
   ```

3. **Verify**:
   ```
   assert(computed_root == header.root.value)
   ```

**Why:** Proves `transcript_commitments` is authentic (not tampered).

### Step 3: Verify Transcript Merkle Proof

**Goal:** Prove revealed HTTP data is in `transcript_commitments[0]`

**Commitment scheme:** Encoding commitment (blinded chunks + Merkle tree)

**Structure:**
```json
{
  "root": { "alg": 2, "value": [32 bytes] },
  "secret": { "seed": [32 bytes], "delta": [16 bytes] }
}
```

**Process:**

1. **Split transcript into chunks** (16 bytes each)

2. **Decode revealed chunks**:
   ```
   For each chunk_i:
     encoding_key_i = derive_key(secret.seed, secret.delta, i)
     plaintext_i = committed_chunk_i XOR encoding_key_i
   ```

3. **Recompute Merkle tree**:
   ```
   leaf_i = Blake3(plaintext_i)
   Build tree → computed_root
   ```

4. **Verify**:
   ```
   assert(computed_root == transcript_commitment.root.value)
   ```

**Why:** Proves HTTP data is exactly what was transmitted. Cannot modify even one byte.

**Key insight:** Encoding commitment enables selective disclosure - reveal only needed parts.

### Step 4: Verify Server Identity (Optional)

**Goal:** Prove connection was with api.binance.com

**Process:**

1. **Verify TLS certificate chain**:
   - Extract certs from `identity.opening.data.certs`
   - Verify signatures (leaf ← intermediate ← root CA)
   - Check validity period at `connection_info.time`
   - Verify domain matches (`*.binance.com`)

2. **Verify cert_commitment**:
   ```
   computed = Blake3(BCS_serialize(certs))
   assert(computed == body.cert_commitment.value)
   ```

3. **Verify server's ephemeral key** matches TLS handshake

**Why:** Proves connection was with authentic Binance, not impersonator.

### Step 5: Extract Price Data

**Goal:** Get price from authenticated response

**Process:**

1. **Parse HTTP response**:
   ```
   http_response = transcript.received_authed
   body_start = find("\r\n\r\n") + 4
   json_body = http_response[body_start:]
   ```

2. **Parse JSON**:
   ```
   data = JSON.parse(json_body)
   price = data.price  // "123104.96000000"
   ```

3. **Validate**:
   ```
   assert(data.symbol == "BTCUSDT")
   assert(price > 0)
   ```

**Why:** Final extraction of oracle data from authenticated chain.

### What Gets Verified

✅ **Signature**: Notary's ECDSA on Header (Keccak-256)
✅ **Body integrity**: Fields in `header.root` (Blake3 Merkle)
✅ **Transcript authenticity**: HTTP in `transcript_commitments` (encoding + Merkle)
✅ **Server identity**: TLS cert chain valid (X.509)
✅ **Data extraction**: Price from authenticated response

### Security Properties

- **Authenticity**: Data from Binance (if identity verified)
- **Integrity**: Cannot tamper (breaks Merkle proofs)
- **Non-repudiation**: Notary cannot deny signing
- **Timestamp**: Connection time proven
- **Privacy**: Selective disclosure supported

### Implementation Requirements

**Cryptographic primitives needed:**
- BCS serialization (Diem/Sui format)
- Keccak-256 hashing (Ethereum-compatible)
- Blake3 hashing (Merkle trees)
- ECDSA secp256k1 verification
- X.509 certificate parsing (optional)

**Key formats:**
- Header: `{ id: [16]u8, version: u16, root: Hash }`
- Signature: `{ alg: u8, data: [65]u8 }` (r || s || v)
- Hash: `{ alg: u8, value: [32]u8 }`


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


## Resources

- **TLSNotary Docs**: https://docs.tlsnotary.org
- **Noir Lang**: https://noir-lang.org
- **Source Code**: [crates/examples/binance_oracle_server.rs](crates/examples/binance_oracle_server.rs)
- **Example Verification**: [crates/examples/verify_presentation.rs](crates/examples/verify_presentation.rs)
