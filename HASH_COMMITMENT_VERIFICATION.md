# Hash Commitment Verification in TLSNotary

This document explains how hash commitments work in the TLSNotary protocol and how to verify them.

## Overview

The TLSNotary protocol uses hash commitments to allow selective disclosure of data from a TLS session. The prover can commit to data during the TLS session and later selectively reveal parts of it.

## Two-Level Hash Structure

There are TWO different hashes involved:

### 1. Committed Hash (Hash Opening)
```
committed_hash = SHA256(full_plaintext || blinder)
```

This is the hash that can be "opened" by revealing:
- The full plaintext (e.g., entire HTTP response)
- The blinder (16-byte random value)

**Purpose**: Allows the prover to later prove they know the plaintext that hashes to this commitment.

### 2. Field Hash (Merkle Tree Leaf)
```
field_hash = hash_separated(PlaintextHash)
```

Where `PlaintextHash` is a structure containing:
- `direction`: Sent or Received
- `idx`: Index ranges in the transcript
- `hash`: The committed_hash from step 1

**Purpose**: This is what actually goes into the Merkle tree and gets signed by the notary.

## Complete Verification Chain

To fully verify a TLSNotary proof with hash commitments, you need to verify:

### Step 1: Hash Opening
Verify that the revealed plaintext and blinder hash to the committed hash:

```rust
let mut preimage = Vec::new();
preimage.extend_from_slice(&full_plaintext); // ENTIRE committed range
preimage.extend_from_slice(&blinder);
let computed = SHA256(preimage);
assert_eq!(computed, committed_hash);
```

**Important**: The hash is computed over the ENTIRE committed plaintext, not just the selective disclosure.

### Step 2: Field Hash in Body
The `committed_hash` from Step 1 is embedded in a `PlaintextHash` structure, which is then:
1. Serialized using canonical serialization
2. Hashed with a domain separator
3. Placed in the attestation body as a field

This produces the `field_hash` that goes in the Merkle tree.

### Step 3: Merkle Proof
Verify that the `field_hash` is in the Merkle tree root:

```
field_hashes = [hash(field_0), hash(field_1), ..., field_hash, ...]
merkle_root = MerkleTree(field_hashes).root()
```

The Merkle proof shows that `field_hash` is included in `merkle_root`.

### Step 4: Notary Signature
Verify the notary's signature on the header, which contains the `merkle_root`:

```
notary.verify_signature(header, signature)
```

## Why Two Hashes?

1. **Committed Hash**: Used for hash opening - allows proving you know the preimage
2. **Field Hash**: Used for Merkle tree - prevents type confusion attacks and enables selective disclosure of different commitment types

## Example: Binance Oracle

In the `binance_oracle_server.rs` example:

1. **Commitment Phase**:
   - Commit to the entire HTTP response (945 bytes)
   - `committed_hash = SHA256(full_http_response || random_blinder)`

2. **Disclosure Phase**:
   - Reveal the full HTTP response and blinder
   - Specify the location of the price within the response (bytes 928-943)

3. **Verification**:
   - Hash opening: Verify `SHA256(response || blinder) == committed_hash`
   - Extract price from bytes 928-943 of the response
   - Verify Merkle proof: `field_hash` is in signed `merkle_root`
   - Verify notary signature on the header

## Common Pitfalls

### ❌ Wrong: Hashing only the selective disclosure
```rust
// This will NOT match!
let wrong = SHA256(price_only || blinder);
```

### ✅ Correct: Hashing the full committed plaintext
```rust
// This matches the commitment
let correct = SHA256(full_http_response || blinder);
```

### Why?
The commitment is created BEFORE selective disclosure. It commits to the entire range, and then you can selectively reveal parts of it. The hash opening must verify against the full committed plaintext.

## On-Chain Verification

For verifying in a smart contract (e.g., Solidity or Noir):

```solidity
function verify(
    bytes memory fullPlaintext,
    bytes memory blinder,
    bytes32 committedHash,
    bytes32 merkleRoot,
    bytes32[] memory merkleProof,
    bytes memory notarySignature
) public returns (bool) {
    // 1. Verify hash opening
    bytes32 computed = keccak256(abi.encodePacked(fullPlaintext, blinder));
    require(computed == committedHash, "Hash opening failed");

    // 2. Verify Merkle proof
    bytes32 fieldHash = computeFieldHash(committedHash, direction, idx);
    require(verifyMerkleProof(fieldHash, merkleRoot, merkleProof), "Merkle proof failed");

    // 3. Verify notary signature
    require(verifySignature(merkleRoot, notarySignature, notaryPubkey), "Signature failed");

    // 4. Extract and use the data
    bytes memory price = extractPrice(fullPlaintext, priceStart, priceEnd);
    return true;
}
```

## References

- Core hash commitment code: `crates/core/src/transcript/hash.rs`
- Hash algorithm implementations: `crates/core/src/hash.rs`
- Attestation body hashing: `crates/core/src/attestation.rs::hash_fields()`
- Example usage: `crates/examples/binance_oracle_server.rs`
