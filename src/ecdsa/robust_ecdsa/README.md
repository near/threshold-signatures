# Robust Threshold ECDSA (`src/ecdsa/robust_ecdsa/`)

This module implements an amended version of the threshold ECDSA scheme from \[[DJNPO20](https://eprint.iacr.org/2020/501)\]. Unlike OT-based ECDSA, it avoids Beaver triple generation entirely -- the offline phase consists of a single presigning protocol using degree-2t polynomials.

The amendment relaxes security from active adversaries to honest-but-curious, intended for deployment inside a Trusted Execution Environment (TEE) that prevents adversarial deviation.

## Pipeline

```
Presigning (offline)  -->  Signing (online)
  3 rounds                   1 round
```

Each presignature is consumed **exactly once** (one-time use).

## Modules

### `presign.rs`

Three-round presigning protocol. Each participant generates 5 polynomials (2 degree-t, 3 degree-2t) and exchanges evaluations to produce a `PresignOutput` containing `(R, c, e, alpha, beta)`.

**Round 1**: Generate random polynomials for nonce `k`, mask `a`, and blinding factors `b`, `d`, `e`; privately send evaluations to all other participants.

**Round 2**: Sum received shares, compute local values, broadcast `(R_i, w_i)` where `R_i = g^{k_i}` and `w_i = a_i * k_i + b_i`.

**Round 3**: Verify exponent interpolation of R values, compute final `R` via interpolation at x=0, derive signature share components `(c, e, alpha, beta)`.

### `sign.rs`

One-round online signing protocol. Takes a `RerandomizedPresignOutput` and the message hash, then produces the final ECDSA `Signature`. Non-coordinators send signature shares privately to the coordinator, who aggregates, normalizes to low-S form, and verifies the result.

## Types

- **`PresignArguments`** -- input to presigning: keygen output + `MaxMalicious` threshold
- **`PresignOutput`** -- presignature: `(big_r, c, e, alpha, beta)`, serializable, zeroize-on-drop
- **`RerandomizedPresignOutput`** -- presignature after rerandomization via HKDF-SHA3-256 for a specific message/context

## Threshold

The threshold parameter is `MaxMalicious(t)`, tolerating up to `t` Byzantine participants. Both presigning and signing require **exactly** `N = 2t + 1` participants. This constraint is enforced at initialization and prevents split-view attacks where different subsets sign different messages using shares from the same presignature.

Additionally, `msg_hash == 0` is rejected to prevent a related-key split-view attack.

## Further Reading

- [`docs/ecdsa/robust_ecdsa/signing.md`](../../../docs/ecdsa/robust_ecdsa/signing.md) -- protocol specification with security analysis
- [`docs/ecdsa/preliminaries.md`](../../../docs/ecdsa/preliminaries.md) -- standard ECDSA recap
- [Parent ECDSA README](../README.md) -- comparison with OT-based ECDSA
