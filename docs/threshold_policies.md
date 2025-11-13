# Threshold Policies & Security Assumptions

This document defines the **non-negotiable invariants** between participant count `N`, tolerated malicious parties `f`, reconstruction threshold `t`, and liveness requirements. All protocols in this repository **must** enforce these rules unless a future `SchemeRules` table explicitly allows an exception.

## Global Principle

**The tuple `(N, f, t)` chosen at key generation is fixed for all subprotocols**  
(keygen → presign/offline → signing → refresh → resharing).  
Any deviation **must be rejected** unless explicitly whitelisted by `SchemeRules`.

_If a different threshold is needed, run a new DKG._

## Why invariance is mandatory

Changing thresholds at any stage can silently weaken security (e.g., reducing signing quorum, increasing adversarial influence, or invalidating proofs from DKG). Recent industry incidents show this is a practical risk. The library therefore enforces all parameters unless explicitly allowed.

## ThresholdPolicy & SchemeRules

- **ThresholdPolicy:**  
  Defines which parameters (`N`, `f`, `t`, participant set) must remain invariant.  
  Default: **full invariance across all subprotocols**.

- **SchemeRules:**  
  Future, scheme-specific exceptions.  
  No exceptions exist today; all protocols must treat thresholds as fixed.

## Persistence Requirement

All keys, shares, or transcripts that leave the protocol must embed `(N, f, t)` so future API calls can enforce invariants even if the caller did not store them.

---

# Scheme-Specific Constraints

## Distributed Key Generation (DKG)

- **Fault tolerance:**  
  `f <= floor(N / 3)` due to asynchronous reliable broadcast.
- **Threshold:**  
  `t = f + 1` (design choice; distinct from `N - f`).
- **Required checks:**
  - Reject if `f >= N / 3`.
  - Reject if `t != f + 1`.
- **Invariance:**  
  DKG → refresh → resharing all reuse the exact `(N, f, t)`.

## OT-based ECDSA

- **Definitions:**  
  `f = max_malicious_parties`, `t = f + 1`.
- **Liveness:**  
  Signing/presigning requires `N_live >= t`.
- **Threshold consistency:**  
  Any mismatch between supplied `(f, t)` must be rejected.
- **Invariance:**  
  Keygen, triple generation, presign, sign, refresh all share the same `(f, t)`.

## Robust ECDSA (secret-sharing-based)

- **Parameterization:**  
  Scheme is defined by `f`; effective threshold derived from `f`.
- **Liveness:**  
  Signing requires `N_live >= 2f + 1`.  
  If this fails, resharing is required before signing.
- **Invariance:**  
  `f` remains constant across keygen, presign (if present), signing, refresh.  
  (Future SchemeRules may allow `N_live` to exceed offline `N`, but not implemented yet.)

---

# Refresh & Resharing Safety

- Never change thresholds during refresh/resharing. Doing so breaks the assumptions of all supported schemes.
- To adopt a new threshold: **Perform a new DKG**, archive the old key, and migrate intentionally.
- Threshold metadata must always be persisted together with key/share identifiers.

---

# Consequences of Misconfiguration

| Misconfiguration                            | Failure Mode                                                          |
| ------------------------------------------- | --------------------------------------------------------------------- |
| `f >= N/3` in DKG                           | Broadcast assumptions break; safety and liveness lost.                |
| `t != f + 1` in DKG or OT-ECDSA             | Scheme assumptions violated; security/liveness not guaranteed.        |
| Threshold lowered during refresh            | Old shares become over-powerful; confidentiality/unforgeability fail. |
| Robust ECDSA signing with `N_live < 2f + 1` | Protocol aborts or risks leakage/invalid signatures.                  |

---

If a scheme allows different parameters between subprotocols, the corresponding `SchemeRules` entry **must** document the exact conditions.
