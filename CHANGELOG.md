# Changelog

## [0.2.0] — Threshold metadata enforcement

**Highlights**

- `KeygenOutput` now serializes a `ThresholdParameters` struct so thresholds are
  persisted with every key/share. APIs such as `refresh` consume this metadata
  directly, preventing callers from silently changing the threshold across
  subprotocols.
- `refresh` signature changed to `refresh(&KeygenOutput, &[Participant], me, rng)`.
- `docs/threshold_policies.md` updated to describe the new persistence rules
  and high-visibility warnings were added to `README.md`.

**Migration steps**

1. **Update stored key material:** If you serialize `KeygenOutput`, add support
   for the new `threshold_params` field (or re-run keygen with 0.2.0 to regenerate
   keys that include it).
2. **Adjust refresh calls:** Replace previous `refresh` invocations with the new
   signature by passing the entire `KeygenOutput` instead of separate share
   and threshold arguments.
3. **Reshare inputs:** When calling `reshare`, feed in the `threshold_params`
   extracted from existing keys to satisfy the enforced invariants.

All other APIs retain their semantics, but will now error if provided threshold
values differ from the persisted metadata.

---

## [0.1.0] — Initial release

*Original audited release prior to explicit threshold enforcement.*
