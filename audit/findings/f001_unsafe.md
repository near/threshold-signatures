# Unsafe Code Analysis Report

This document serves as a comprehensive report for all instances of `unsafe` code usage within the project. Each entry details the diagnosis, required invariants, potential failure modes, and remediation steps for a specific `unsafe` block.

---

## Potential Issue #1 [[strobe.rs](../../src/crypto/proofs/strobe.rs#38)]

### Diagnosis
`unsafe` usage may cause [UB](https://doc.rust-lang.org/reference/behavior-considered-undefined.html) if invariants not met.

<details>
<summary>Click to expand the full analysis</summary>

#### The `unsafe` block

```rust
fn transmute_state(st: &mut AlignedKeccakState) -> &mut [u64; 25] {
    unsafe { &mut *(st as *mut AlignedKeccakState as *mut [u64; 25]) }
}
```

#### Purpose
This function casts a mutable reference to `AlignedKeccakState` (a 200-byte array with 8-byte alignment) into a mutable reference to a `[u64; 25]` array. This is a **performance optimization** to allow the Keccak permutation function to operate on 64-bit words directly, **avoiding memory copies**.

#### Required Invariants

List of conditions that **must** be met for this `unsafe` operation to be sound. 
1.  **Size Equality**: `sizeof(AlignedKeccakState)` must equal `sizeof([u64; 25])`. (200 bytes).
2.  **Alignment**: `alignof(AlignedKeccakState)` must be at least `alignof(u64)`, which is 8. The `#[repr(align(8))]` attribute on `AlignedKeccakState` correctly enforces this.
3.  **Endianness**: The target executing the code must be little-endian (e.g x86_64, etc)

### Potential Failure Modes

How these invariants could be violated, leading to Undefined Behavior or incorrect results:
1.  **Code Evolution**: If a future modification changes the size or alignment of `AlignedKeccakState` without updating this `unsafe` block, it will cause Undefined Behavior.
2.  **Endianness**: This is the most critical risk. The cast reinterprets bytes as `u64` words based on the **native endianness** of the CPU. The Keccak standard requires a **little-endian** interpretation. This code will produce incorrect results on big-endian architectures, breaking cryptographic correctness and interoperability.

</details>

### Remediation

The steps taken to mitigate the identified risks:

| Status | Mitigation | Effectiveness |
| :---: | :--- | :--- |
| ✅ **Done** | Unit Tests + Dev Comments to mitigate Code Evolution risk  | [Very High]. A [unit test](../../src/crypto/proofs/strobe.rs#L205) is added to detect regression. |
| ✅ **Done** |Unsafe Soundness | [Very High]. [Kani](../../src/crypto/proofs/strobe_kani.rs) Proves the soundness. |
| ⬜️ **To Do** | CI Endianness | - |

---
