# Internal Security Audit

This is a **living, developer-led security audit** of the `threshold-signatures` codebase.  
Work is in public; findings and progress are continuously updated.

---

## Overview

- ✅ Purpose: Identify risks and harden critical paths.
- ✅ Focus: `unsafe` code, critical paths, fuzzing, formal proofs.
- ✅ Current state:  
  - [Progress Snapshot](./progress.md)  
  - [Findings Log](./findings.md)

<details>
<summary>See full Purpose & Scope</summary>

Goals:

- Identify `unsafe` code usage
- Map critical paths and attack surfaces
- Ensure high test coverage
- Plan fuzzing & formal proofs
- Document and track risks
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
