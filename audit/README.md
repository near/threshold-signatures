# Internal Security Audit

This is a **living, developer-led security audit** of the `threshold-signatures` codebase.  
Work is in public; findings and progress are continuously updated.

---

## Overview

- ✅ Purpose: Identify risks and harden critical paths.
- ✅ Focus: `unsafe` code, critical paths, fuzzing, formal proofs.
- ✅ Current state: [Findings & progress](#findings)

<details>
<summary>See full Purpose & Scope</summary>

Goals:

- Identify `unsafe` code usage (in dependencies and related call sites)
- Map security-critical paths and attack surfaces
- Ensure high test coverage for critical paths
- Plan fuzzing campaigns and formally prove correctness where feasible
- Document and track risks
</details>

---

## Findings

<details>
<summary>View current findings & remediation status</summary>

[Tracked in `findings.md`](./findings.md)

</details>

---

## Progress Snapshot

| Task                                      | Status |
| ----------------------------------------- | ------ |
| Add audit structure and initial analysis  | ✅     |
| Verify `unsafe` soundness with Kani       | ✅     |
| Identify `unsafe` in dependencies         | ⬜     |
| Verify call sites interacting with `unsafe` deps | ⬜     |
| Expand CI to run proofs & sanitizers      | ⬜     |
| Map critical paths & attack surfaces      | ⬜     |
| Ensure high test coverage                 | ⬜     |
| Review cryptographic state transitions    | ⬜     |

<details>
<summary>See detailed methodology & tooling</summary>

| Goal                      | Tooling                   |
| ------------------------- | ------------------------- |
| Detect undefined behavior | `miri`, sanitizers        |
| Prove correctness         | `kani`, model checking    |
| Fuzz unsafe code          | `cargo-fuzz`, `honggfuzz` |
| Check coverage            | `cargo-llvm-cov`          |

- `miri` & sanitizers on critical paths
- `kani` formal verification of key functions
- Fuzzers target unsafe blocks & edge cases
- Coverage reports highlight untested paths
</details>

---

## Disclaimer

<blockquote style="border-left: 4px solid orange; padding: 0.5em;">
<b>⚠️ Note:</b>

This audit is **NOT a professional, third-party security audit**.  
It is a preliminary developer-led effort to proactively harden the codebase.
</blockquote>

---

## Contributing

<details>
<summary>Click to see contribution steps</summary>

1. Install [Kani](https://github.com/model-checking/kani?tab=readme-ov-file#installation)  
2. Clone repository: `git clone --depth 1 https://github.com/near/threshold-signatures/`  
3. Run tests: `cd threshold-signatures && cargo test && cargo kani`  
4. Add new findings under `audit/`  
5. Open PRs or issues tagged `dev-audit`  
</details>
