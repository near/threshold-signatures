# FROST-based Threshold Signatures (`src/frost/`)

This module implements threshold signature schemes based on the [FROST](https://github.com/ZcashFoundation/frost) (Flexible Round-Optimized Schnorr Threshold) framework.

## Schemes

### EdDSA / Ed25519 (`eddsa/`)

Threshold Ed25519 signing following [RFC 9591](https://www.rfc-editor.org/rfc/rfc9591.html). Wraps the `frost-ed25519` crate's `round1`, `round2`, and `aggregate` functions into this library's `Protocol` interface.

**Key characteristics:**
- **No offline phase** -- signing is a 2-round online protocol
- **Round 1**: Each party generates nonce commitments; coordinator collects and distributes them
- **Round 2**: Each party computes a signature share; coordinator aggregates into a standard Ed25519 signature
- Produces signatures verifiable by any standard Ed25519 verifier

**Note:** Unlike ECDSA, the EdDSA implementation does *not* outsource message hashing -- it internally performs the hash as part of the signing protocol.

### RedJubJub (`redjubjub/`)

Threshold RedDSA signing on the JubJub curve, compatible with Zcash Sapling spend authorization signatures (ZIP-0312). Uses a [NEAR fork](https://github.com/near/reddsa) of the `reddsa` crate.

**Key characteristics:**
- Split into **presign** (round 1: nonce commitment exchange) and **sign** (round 2: share computation + aggregation)
- The presign/sign split allows the nonce exchange to happen before the message is known
- Produces signatures compatible with Zcash Spend Authorization verification

## Shared Logic (`mod.rs`)

`assert_sign_inputs` -- common input validation for both schemes (participant list deduplication, threshold checks, self-inclusion, coordinator inclusion).

## DKG

Both schemes use the same curve-generic DKG from the [root API](../lib.rs):
- Ed25519: `keygen::<Ed25519Sha512>(...)`
- RedJubJub: `keygen::<JubjubBlake2b512>(...)`

## Further Reading

- [`docs/eddsa/signing.md`](../../docs/eddsa/signing.md) -- EdDSA signing protocol specification
- [Main README](../../README.md) -- overview of EdDSA functionalities
