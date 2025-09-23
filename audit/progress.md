[<-](./README.md)
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

---
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
