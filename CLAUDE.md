# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Test Commands

### Quick Reference
```bash
# Build
cargo build --profile test-release --all-features  # Build (same profile as tests)

# Test
cargo nextest run --all-features --profile test-release  # All tests
cargo nextest run --all-features --profile test-release -E 'test(test_name)'  # Single test

# Linting and checks
cargo make check-all                           # All checks: fmt + check + clippy + test + deny
cargo clippy --all-features --all-targets --locked -- -D warnings
cargo fmt -- --check
cargo deny --all-features check                # License and advisory audit

# Benchmarks (require test-utils feature)
cargo bench --bench bench_name --features test-utils
```

### Available cargo-make tasks
- `cargo make check-all` — fmt + check + clippy + test + deny (the full CI suite)
- `cargo make test` — tests with `--profile test-release --all-features`
- `cargo make clippy` — strict clippy (`-D warnings`)
- `cargo make fmt` / `cargo make fmt-fix` — check / fix formatting
- `cargo make deny` — cargo-deny license/advisory checks

## Architecture Overview

This is a **threshold signature cryptography library** — a single Rust crate implementing multiple threshold signature schemes for NEAR's MPC signing service. Multiple parties collaboratively sign messages without any single party possessing the complete private key.

### Cryptographic Schemes

| Scheme | Curve | Module | Description |
|--------|-------|--------|-------------|
| **OT-based Threshold ECDSA** | Secp256k1 | `src/ecdsa/ot_based_ecdsa/` | Beaver triple-based presigning via oblivious transfer |
| **Robust Threshold ECDSA** | Secp256k1 | `src/ecdsa/robust_ecdsa/` | Triple-free presigning, tolerates `MaxMalicious` faults |
| **Threshold EdDSA (FROST)** | Ed25519 | `src/frost/eddsa/` | FROST-based Ed25519, no offline phase |
| **Threshold RedJubJub (FROST)** | JubJub | `src/frost/redjubjub/` | Zcash Sapling spend authorization |
| **Confidential Key Derivation** | BLS12-381 | `src/confidential_key_derivation/` | BLS signatures + ElGamal encryption |
| **DKG (curve-agnostic)** | All above | `src/dkg.rs` | Distributed key generation, resharing, refresh |

### Module Structure

```
src/
  lib.rs                    # Public API: keygen, reshare, refresh, Tweak, KeygenOutput
  dkg.rs                    # Curve-agnostic DKG and resharing
  participants.rs           # Participant, ParticipantList, ParticipantMap, ParticipantCounter
  thresholds.rs             # MaxMalicious, ReconstructionLowerBound
  errors.rs                 # ProtocolError, InitializationError

  crypto/                   # Shared cryptographic primitives
    ciphersuite.rs          #   Ciphersuite trait (extends frost_core::Ciphersuite)
    polynomials.rs          #   Shamir secret-sharing, Lagrange coefficients
    proofs/                 #   Sigma proofs: dlog (Maurer09), dlog equality
    hash.rs, commitment.rs  #   Domain-separated hashing, commitments

  ecdsa/                    # Secp256k1 ECDSA schemes
    ot_based_ecdsa/         #   OT-based: triples/, presign, sign
    robust_ecdsa/           #   Robust: presign, sign

  frost/                    # FROST-based schemes
    eddsa/                  #   Ed25519 signing
    redjubjub/              #   RedJubJub presign + sign

  confidential_key_derivation/  # BLS12-381 CKD protocol

  protocol/                 # Protocol execution infrastructure
    internal.rs             #   ProtocolExecutor, SharedChannel, PrivateChannel
    echo_broadcast.rs       #   Reliable broadcast (Send/Echo/Ready)

  test_utils/               # Behind feature flag "test-utils"
    mockrng.rs              #   MockCryptoRng for deterministic tests
    participant_simulation.rs  # Simulator for multi-party protocols
    protocol.rs             #   run_protocol, run_simulated_protocol
```

### Protocol Pattern

Protocols follow a consistent architecture:
1. Written as `async fn` using `SharedChannel` (broadcast) and `PrivateChannel` (point-to-point)
2. Wrapped into the synchronous `Protocol` trait via `make_protocol()` / `ProtocolExecutor`
3. Messages serialized with MessagePack (`rmp_serde`), prefixed with SHA-256-derived headers
4. `ParticipantMap` / `ParticipantCounter` collect one message per participant per round

## Coding Conventions

### Naming
- `do_*` prefix for internal async protocol functions (e.g., `do_keygen`, `do_ckd_participant`)
- Math variables follow cryptographic notation: `big_r` for curve points, lowercase for scalars
- Type aliases per scheme (e.g., `pub type KeygenOutput = crate::KeygenOutput<Secp256K1Sha256>`)

### Error Handling
- `InitializationError` for bad parameters before a protocol starts
- `ProtocolError` for errors during protocol execution (has `Other(String)` catch-all)
- Both use `thiserror`

### Clippy Strictness
- **Denied in production**: `indexing_slicing`, `panic`
- **Warned in production**: `unwrap_used`, `panic_in_result_fn`, full `pedantic` + `nursery` groups
- **Allowed in tests**: `clippy.toml` exempts test code from `unwrap_used`, `panic`, `indexing_slicing`

### Testing
- **Unit tests**: `#[cfg(test)] mod test` inside source files
- **Integration tests**: `tests/` directory (robust_ecdsa, ckd, eddsa)
- **Snapshot tests**: `insta` crate with stored snapshots in `snapshots/` subdirectories
- **Determinism**: Tests use `MockCryptoRng::seed_from_u64(42)` for reproducible results
- **Simulator**: `run_protocol()` / `run_simulated_protocol()` orchestrate multi-party execution in-process
- **Profile**: Tests run under `test-release` profile (release optimizations + overflow checks + debug info)

### Key Dependencies
- `frost-core`/`frost-ed25519`/`frost-secp256k1` (v2.2.0) — FROST framework
- `reddsa` (NEAR fork) — RedJubJub
- `blstrs` — BLS12-381
- `k256` — Secp256k1
- `zeroize` — Secure memory zeroing for secrets
- `rand_core` pinned to v0.6.4 for `frost-core` compatibility

## CI Tools Required

- `cargo-make` (task runner)
- `cargo-deny` (license/advisory audit)
- `cargo-nextest` (fast test runner, used in CI)
- `zizmor` (GitHub Actions security)
