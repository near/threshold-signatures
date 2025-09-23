[<-](../findings.md)
# [YOUR] Report

[SUMMARY]

---

## Potential Issue: [FILE_NAME](PATH#LINE_NUMBER)

### Diagnosis

[QUICK TAKEAWAY]

<details>
<summary>Click to expand the full analysis</summary>

#### THE POTENTIAL ISSUE

```rust
// Paste the relevant code block or function here
```

#### Purpose
[Explain the purpose of the code block and why it's necessary. What problem does it solve that cannot be solved the other way?]

#### Required Invariants

[List the conditions that **must** be met for this operation to be safe. Be precise about memory, type, and logical invariants.]
1.  **[Invariant 1]**: [Description]
2.  **[Invariant 2]**: [Description]
3.  ...

#### Potential Failure Modes

[Describe how these invariants could be violated, leading to Undefined Behavior or incorrect results.]
1.  **[Failure Mode 1]**: [Description]
2.  **[Failure Mode 2]**: [Description]
3.  ...

</details>

### Remediation

This section tracks the steps taken to mitigate the identified risks for this specific instance.

| Status | Mitigation | Effectiveness |
| :---: | :--- | :--- |
| ⬜️ **To Do** / ✅ **Done** | **[Mitigation Strategy 1]** | **[Low/Medium/High/Very High].** [Detailed description of the mitigation, including links to relevant code (e.g., unit tests, formal proofs, documentation).] |
| ⬜️ **To Do** / ✅ **Done** | **[Mitigation Strategy 2]** | **[Low/Medium/High/Very High].** [Detailed description.] |
| ... | ... | ... |

---

## Potential Issue: [FILE_NAME](PATH#LINE_NUMBER)

... (Repeat the structure above for each instance)