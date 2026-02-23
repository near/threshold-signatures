# Cryptographic Primitives (`src/crypto/`)

This module contains the shared cryptographic building blocks used across all threshold signature schemes in this library.

## Modules

### `ciphersuite.rs`

Defines the library's [`Ciphersuite`](ciphersuite.rs) trait, which extends `frost_core::Ciphersuite` with scalar byte-ordering metadata (`BytesOrder`). Every signature scheme implements this trait:

| Type | Curve | Byte Order |
|------|-------|------------|
| `Secp256K1Sha256` | Secp256k1 | Big-endian |
| `Ed25519Sha512` | Curve25519 | Little-endian |
| `JubjubBlake2b512` | JubJub | Little-endian |
| `BLS12381SHA256` | BLS12-381 (G2) | Little-endian |

The byte ordering is critical for `Participant::scalar<C>()`, which converts participant IDs into field elements for Lagrange interpolation.

### `polynomials.rs`

Shamir secret-sharing arithmetic:
- `Polynomial<C>` -- polynomial with scalar coefficients (constant term first)
- `PolynomialCommitment<C>` -- commitments to polynomial coefficients (EC points)
- Lagrange coefficient computation (`compute_lagrange_coefficient`, `batch_compute_lagrange_coefficients`)
- `batch_invert` for efficient multi-scalar inversion

Used in DKG for secret sharing and in Robust ECDSA for exponent interpolation.

### `commitment.rs`

A binding and perfectly hiding hash commitment scheme: `SHA256(NEAR_COMMIT_LABEL || randomness || START_LABEL || msgpack(value))`. Used in DKG round 1 and triple generation for committing to polynomial data before sending to all parties.

### `hash.rs`

Domain-separated SHA-256 hashing:
- `HashOutput` -- typed 32-byte output with constant-time equality
- `hash(value)` -- serializes via MessagePack then hashes with a domain label
- `domain_separate_hash` -- for additional domain separation in DKG and echo broadcast

### `random.rs`

Randomness generation utilities used alongside the commitment scheme.

### `constants.rs`

Domain separation strings (`NEAR_HASH_LABEL`, `NEAR_CHANNEL_TAGS_DOMAIN`, `NEAR_CKD_DOMAIN`, etc.) ensuring cryptographic isolation between different protocol contexts.

### `proofs/`

Maurer \[[Mau09](https://crypto.ethz.ch/publications/files/Maurer09.pdf)\] NIZK proofs via Fiat-Shamir. See [`proofs/README.md`](proofs/README.md) and the detailed documentation at [`docs/crypto/proofs.md`](../../docs/crypto/proofs.md).

## Further Reading

- [DKG documentation](../../docs/dkg.md) -- how polynomials, commitments, and proofs come together in distributed key generation
- [Proofs documentation](../../docs/crypto/proofs.md) -- formal specification of the Maurer proof framework
