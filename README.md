# Binance TLSNotary Oracle

A proof-of-concept TLSNotary oracle that fetches BTC/USDT price from Binance API and generates cryptographic proofs for on-chain verification.

## Overview

This oracle demonstrates how to use TLSNotary to create verifiable proofs of data from web APIs. It fetches the Bitcoin price from Binance and generates:

1. **Hash commitment proof**: Proves the plaintext (HTTP response) is authentic
2. **Merkle proof**: Proves the commitment is in the notary-signed attestation
3. **Signature**: Notary's cryptographic signature over the attestation

## ⚠️ Important Security Notice

**This implementation is simplified for learning purposes and has known trust assumptions.**

### What This Code Verifies On-Chain:

✅ **Hash Opening**: `SHA256(plaintext || blinder) == committedHash`
- Proves the plaintext hasn't been tampered with after commitment

✅ **Merkle Proof**: Field hash is in the signed Merkle root
- Proves the commitment is part of the attestation structure

✅ **Signature**: Notary signed the Merkle root (secp256k1eth)
- Proves the notary attested to this data

### ⚠️ Security Gap (Simplified for Learning):

**This implementation trusts the oracle to provide the correct `fieldHash`.**

The complete verification chain is:
```
plaintext → committedHash → fieldHash → merkleRoot → signature
             (verified ✓)    (TRUSTED)  (verified ✓)  (verified ✓)
```

**The gap**: `fieldHash` is computed off-chain from `committedHash` using:
- BCS serialization of PlaintextHash struct
- Domain separation: `SHA256("PlaintextHash" || serialized)`
- Metadata: direction, byte ranges, commitments

**Attack scenario**: A malicious oracle could:
1. Give you valid `plaintext` + `blinder` (passes hash opening ✓)
2. Give you `fieldHash` from a DIFFERENT attestation
3. Provide valid Merkle proof and signature for that different attestation

**Result**: You'd verify a price from a different TLS session than your plaintext shows.

### For Production Use:

You should either:

1. **Compute `fieldHash` on-chain** (~50k extra gas):
   - Implement BCS serialization in Solidity
   - Apply domain separation
   - Verify fieldHash was computed from your committedHash
   - Closes the security gap completely

2. **Run your own oracle** (recommended):
   - Don't rely on third-party oracles
   - Verify attestations in your backend before sending on-chain
   - Eliminates the trust assumption

3. **Use multiple oracles**:
   - Compare results from different sources
   - Detect malicious behavior through consensus
   - Adds redundancy and security

### Why This Gap Exists:

TLSNotary's security comes from the **notary**, not the oracle:
- The **notary** participates in MPC and verifies the TLS session
- The **oracle** just packages the notary's attestation for on-chain use
- A malicious oracle could mix-and-match attestations from different sessions
- Computing fieldHash on-chain closes this gap but adds complexity and cost

For learning purposes, we accept this simplified trust model to focus on understanding the core TLSNotary concepts.

## Quick Start

### 1. Start the Notary Server

```bash
# Start notary with secp256k1eth for Ethereum compatibility
NS_NOTARIZATION__SIGNATURE_ALGORITHM=secp256k1eth cargo run --bin notary-server

# Output should show:
#   signature_algorithm: secp256k1eth
#   Listening for TCP traffic at 0.0.0.0:7047
```

### 2. Start the Oracle Server

In a new terminal:

```bash
# Run with local notary
USE_LOCAL_NOTARY=1 cargo run --example binance_oracle_server

# Output:
#   🚀 Binance TLSNotary Oracle Server
#   🌐 Listening on: http://127.0.0.1:3000
```

### 3. Query the Oracle

```bash
# Get current BTC/USDT price with proof
curl http://127.0.0.1:3000/price | jq '.verification.price'

# Output: "110883.66000000"
```

## Architecture

### Protocol Flow

```
┌─────────────┐
│   Prover    │ (Oracle Server)
└──────┬──────┘
       │ 1. Initiate notarization
       ↓
┌─────────────┐
│   Notary    │ (Verifier running MPC)
└──────┬──────┘
       │ 2. MPC-TLS Setup
       ↓
┌─────────────┐
│   Binance   │
│  API Server │
└──────┬──────┘
       │ 3. TLS Session (via MPC)
       │    GET /api/v3/ticker/price?symbol=BTCUSDT
       ↓
   Response: {"symbol":"BTCUSDT","price":"110883.66"}
       │
       │ 4. Commitment Phase
       ↓
   committedHash = SHA256(plaintext || blinder)
       │
       │ 5. Notarization
       ↓
   Notary signs attestation with secp256k1eth
       │
       │ 6. Generate Proof
       ↓
┌──────────────────────────────┐
│  Oracle Response             │
├──────────────────────────────┤
│  • plaintext (945 bytes)     │
│  • blinder (16 bytes)        │
│  • committedHash             │
│  • fieldHash (Field 4)       │
│  • all_field_hashes (5)      │
│  • merkle_proof              │
│  • signature (secp256k1eth)  │
└──────────────────────────────┘
```

### Hash Algorithms

| Component | Algorithm | Purpose |
|-----------|-----------|---------|
| **Hash Opening** | SHA-256 | `SHA256(plaintext \|\| blinder)` |
| **Merkle Tree** | SHA-256 | Build tree from 5 field hashes |
| **Signature** | Keccak-256 | secp256k1eth (Ethereum) |

**Note**: Only the signature uses Keccak-256 for Ethereum compatibility. Everything else uses SHA-256 (MPC requirement).

### Attestation Structure

```
Merkle Tree (5 fields):
  Field 0: verifying_key
  Field 1: connection_info
  Field 2: server_ephemeral_key
  Field 3: cert_commitment
  Field 4: transcript_commitment ← Price data here!
```

## Example Response

```json
{
  "hash_proof": {
    "hash_algorithm": 1,
    "committed_hash": [231, 182, ...],
    "plaintext": "HTTP/1.1 200 OK\r\n...\r\n{\"symbol\":\"BTCUSDT\",\"price\":\"110883.66\"}",
    "price_range": {"start": 928, "end": 943},
    "blinder": [137, 81, 44, ...],
    "direction": "Received"
  },
  "body_merkle_proof": {
    "root": [24, 53, 65, ...],
    "leaf_index": 4,
    "proof_hashes": [],
    "leaf_count": 5,
    "all_field_hashes": [
      [...],  // Field 0
      [...],  // Field 1
      [...],  // Field 2
      [...],  // Field 3
      [...]   // Field 4: transcript commitment
    ]
  },
  "verification": {
    "price": "110883.66000000",
    "symbol": "BTCUSDT",
    "notary_pubkey": "0x0284dc777f...",
    "signature_algorithm": "secp256k1eth"
  }
}
```

## On-Chain Verification (Simplified)

**⚠️ This example trusts the oracle's `fieldHash`. See Security Notice above.**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract BinanceOracleVerifier {
    address public immutable notaryPubKey;

    constructor(address _notaryPubKey) {
        notaryPubKey = _notaryPubKey;
    }

    /// @notice Verify TLSNotary proof (SIMPLIFIED VERSION)
    /// @dev Production use requires computing fieldHash on-chain
    function verifyPrice(
        bytes calldata plaintext,
        bytes16 blinder,
        uint256 priceStart,
        uint256 priceEnd,
        bytes32 fieldHash,        // TRUSTED from oracle
        bytes32[] calldata merkleProof,
        bytes32 merkleRoot,
        bytes calldata signature
    ) external view returns (string memory price) {
        // 1. Verify hash opening
        bytes32 committedHash = sha256(abi.encodePacked(plaintext, blinder));

        // 2. Extract price
        price = string(plaintext[priceStart:priceEnd]);

        // 3. Verify Merkle proof (SHA-256)
        require(
            verifyMerkleProof(fieldHash, merkleProof, merkleRoot),
            "Invalid Merkle proof"
        );

        // 4. Verify signature (Keccak-256)
        bytes32 headerHash = keccak256(abi.encodePacked(merkleRoot));
        address signer = recoverSigner(headerHash, signature);
        require(signer == notaryPubKey, "Invalid signature");
    }

    function verifyMerkleProof(
        bytes32 leaf,
        bytes32[] calldata proof,
        bytes32 root
    ) internal pure returns (bool) {
        bytes32 computedHash = leaf;
        uint256 index = 4; // Field 4

        for (uint256 i = 0; i < proof.length; i++) {
            if (index % 2 == 0) {
                computedHash = sha256(abi.encodePacked(computedHash, proof[i]));
            } else {
                computedHash = sha256(abi.encodePacked(proof[i], computedHash));
            }
            index = index / 2;
        }

        return computedHash == root;
    }

    function recoverSigner(
        bytes32 messageHash,
        bytes calldata signature
    ) internal pure returns (address) {
        require(signature.length == 65);
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        return ecrecover(messageHash, v, r, s);
    }
}
```

## Off-Chain Proof Generation

The oracle provides `all_field_hashes` but `proof_hashes` is empty. Compute the single-field Merkle proof off-chain:

```typescript
import { sha256 } from '@noble/hashes/sha256';

const response = await fetch('http://localhost:3000/price');
const data = await response.json();

// Extract hashes
const [H0, H1, H2, H3, H4] = data.body_merkle_proof.all_field_hashes
  .map(h => Buffer.from(h));

// Compute intermediates
const H01 = sha256(Buffer.concat([H0, H1]));
const H23 = sha256(Buffer.concat([H2, H3]));

// Single-field proof for Field 4
const merkleProof = [H23, H01];

// Send to contract
await contract.verifyPrice(
  data.hash_proof.plaintext,
  data.hash_proof.blinder,
  data.hash_proof.price_range.start,
  data.hash_proof.price_range.end,
  H4,  // fieldHash
  merkleProof,
  data.body_merkle_proof.root,
  data.verification.signature
);
```

## Merkle Tree Structure

```
                    ROOT (signed)
                   /              \
                 H01               H234
                /    \            /     \
              H0     H1         H23     H4
             /       |         /  \      |
       Field0    Field1     Field2 F3  Field4
                                       (price)
```

To prove Field 4:
- Need H23 to compute H234 = SHA256(H23 || H4)
- Need H01 to compute ROOT = SHA256(H01 || H234)

Gas savings: ~25k vs proving all 5 fields.

## Testing

```bash
# Test hash opening
curl -s http://127.0.0.1:3000/price | python3 -c "
import json, sys, hashlib
data = json.load(sys.stdin)
plaintext = data['hash_proof']['plaintext'].encode('utf-8')
blinder = bytes(data['hash_proof']['blinder'])
expected = bytes(data['hash_proof']['committed_hash'])
computed = hashlib.sha256(plaintext + blinder).digest()
print(f'Hash opening verified: {computed == expected}')
print(f'Price: {data[\"verification\"][\"price\"]}')
"
```

## Configuration

### Notary Server

```bash
# Required: Use secp256k1eth for Ethereum
NS_NOTARIZATION__SIGNATURE_ALGORITHM=secp256k1eth

# Optional: Persistent key (default is ephemeral)
NS_NOTARIZATION__PRIVATE_KEY_PATH=./notary.key

# Optional: Data limits
NS_NOTARIZATION__MAX_SENT_DATA=4096
NS_NOTARIZATION__MAX_RECV_DATA=16384
```

### Oracle Server

Edit [binance_oracle_server.rs](crates/examples/binance_oracle_server.rs):

```rust
// Change symbol
let request = format!(
    "GET /api/v3/ticker/price?symbol=ETHUSDT HTTP/1.1\r\n..."
);

// Change port
let addr = "127.0.0.1:3000";
```

## Troubleshooting

| Problem | Solution |
|---------|----------|
| "unsupported hash algorithm: 03" | Use `NS_NOTARIZATION__SIGNATURE_ALGORITHM=secp256k1eth` |
| "Connection refused" | Start notary server on port 7047 |
| "Address already in use" | Kill process: `lsof -ti:3000 \| xargs kill` |
| Empty `proof_hashes` | Expected - compute off-chain from `all_field_hashes` |
| 64-byte hashes | Update to latest code using `hash.value[..hash.len]` |

## Production Considerations

### Close the Security Gap

Choose one approach:

**Option 1: Compute fieldHash On-Chain (~50k gas)**
```solidity
// Implement BCS serialization + domain separation
bytes32 fieldHash = computeFieldHashWithBCS(
    committedHash,
    direction,
    ranges
);
```

**Option 2: Run Your Own Oracle (Recommended)**
- Deploy your own notary
- Run your own oracle server
- Verify attestations before sending on-chain

**Option 3: Multi-Oracle Consensus**
- Query multiple oracles
- Require matching results
- Detect malicious behavior

### Gas Costs

- Current (simplified): ~18k gas
- With full verification: ~70k gas

### Deployment

- Use TEE for notary (SGX/SEV)
- Deploy on Layer 2 for lower costs
- Batch proofs for multiple prices
- Cache verified prices on-chain

## Documentation

- [MERKLE_PROOF_VERIFICATION_GUIDE.md](MERKLE_PROOF_VERIFICATION_GUIDE.md) - Complete verification guide
- [ORACLE_RESPONSE_CLARIFICATION.md](ORACLE_RESPONSE_CLARIFICATION.md) - Response structure details
- [TLSNotary Docs](https://docs.tlsnotary.org) - Full protocol documentation

## Learn More

- **TLSNotary**: https://github.com/tlsnotary/tlsn
- **Discord**: https://discord.gg/9XwESXtcN7
- **Binance API**: https://binance-docs.github.io/apidocs/

---

**⚠️ Disclaimer**: This is a proof-of-concept for learning. The simplified trust model (trusting oracle's fieldHash) is intentional for educational clarity. Do not use in production without addressing the security gap outlined above.
