# Distribute Key Generation
$$
\newcommand{\maxfaulty}{\textsf{{max\_faulty}}}
$$


We define a variant of the two-round DKG protocol PedPop \[[KG](https://eprint.iacr.org/2020/852.pdf)\].
Our variant, PedPop+ is less efficient, but achieves a notion of simulatability with aborts,
a stronger notion of security than the one promised by plain PedPop.

PedPop+ is a five rounds protocol and makes use in three of its rounds of a reliable broadcast channel. A reliable broadcast is a 3 round protocol,
implying that the total number of PedPop+ rounds 11. The broadcast channel is implemented in `src/protocol/echo_broadcast.rs`.

The implemented DKG serves as a generic one that can be used with multiple different underlying elliptic curves. We thus use it with `Secp256k1` for ECDSA schemes, `Curve25519` for EdDSA scheme, and `BLS12_381` for the confidential key derivation functionality.

## Keygen, Reshare and Refresh

The core of the dkg protocol is implemented in a subfunction called `do_keyshare` and serves for three applications:

* Key generation: denoted in the implementation with `keygen`. It allows a set of parties to jointly generate from scratch a private key share each and a master public key. The master public key should be common for all the participants and should reflect each of the private shares.

* Key resharing: denoted in the implementation with `reshare`. It allows for a set of participants who already own valid private shares to kick away other participants from the pool, create fresh shares for new participants i.e. new joiners to the pool, and/or change the **cryptographic threshold** described in section [Types of Thresholds](#types-of-thresholds).

* Key refresh: denoted in the implementation with `refresh`. It is a special case of the key resharing in which the set of participants stays the same before and after the protocol run and with no changes to the crypto. The goal being that each participant would refresh their signing share without modifying the master public key.

## Types of Thresholds

There are two types of thresholds one has to be aware of: the **asynchronous distributed systems threshold** a.k.a. the **BFT threshold**, and the **cryptography threshold** a.k.a. the **reconstruction threshold**.

The BFT threshold states that the maximum number of faulty nodes a distributed system ($\maxfaulty$) can tolerate while still reaching consensus is at most one-third of the total number of participants $N$. More specifically:
$$\maxfaulty \leq \frac{N - 1}{3}$$

The cryptography threshold refers to the maximum number of necessay malicious parties ($\mathsf{max\textit{\_}malicious}$) a certain scheme can handle without compromising on the security and assuming the existance of an underlying reliable broadcast channel. $\mathsf{max\textit{\_}malicious}$ is scheme dependent and can have a different value than $\maxfaulty$. For instance, in the OT based ECDSA, $\mathsf{max\textit{\_}malicious}$ can be up to $N-1$, but in Robust ECDSA scheme $\mathsf{max\textit{\_}malicious}$ must not exceed $\frac{N - 1}{3}$.

### DKG and thresholds

Due to the fact that PedPop+ utilizes reliable broadcast channel to securely generate private shares, it thus lies on the edge between the asynchronous distributed systems and cryptography. For this reason, we set
$\maxfaulty = \frac{N - 1}{3}$ as an invariable parameter and allow our key generation and key resharing protocols to fix/modify only the $\mathsf{max\textit{\_}malicious}$ threshold depending on the scheme requirements and on the library user's choice.

## Technical Details

Let $P_1, \cdots P_N$ be $N$ different participants, and $\mathsf{max\textit{\_}malicious}$ be the desired cryptography threshold. Let $H_1, H_2, H_3$ be domain separated hash functions.

### Key Generation & Key Resharing

We define PedPop+ key generation in white colour only. The key resharing protocol is the combination of white colored steps and the orange colored ones:

No special inputs are given to the **key generation** protocol beyond the public parameters defined above.

<font color="orange">

The inputs to the **key resharing** are:

1. The old private share $\mathit{old\textit{\_}sk}_i$ that $P_i$ held prior to the key resharing. This value is set to None only if $P_i$ is a freshly new participant.

2. The old participants set $\mathit{old\textit{\_}signers}$ that held valid private shares prior to the key resharing.

3. The old master public key $\mathit{old\textit{\_}pk}$ that the $\mathit{old\textit{\_}signers}$ held prior to the key resharing.

4. The old cryptography threshold $\mathit{old\textit{\_}max\textit{\_}malicious}$ prior to the key resharing.

</font>

**Round 1:**

1. Each $P_i$ asserts that $1 < \mathsf{max\textit{\_}malicious} < N$.

<font color="orange">

$\quad$ ++ Each $P_i$ sets $I \gets \set{P_1 \ldots P_N} \cap \mathit{old\textit{\_}signers}$

$\quad$ ++ Each $P_i$ asserts that $\mathsf{old\textit{\_}max\textit{\_}malicious} \leq \# I$.

</font>

2. Each $P_i$ generates a random 32-byte sesssion identifier $\mathit{sid}_i$

3. Each $P_i$ reliably broadcasts $\mathit{sid}_i$

**Round 2:**

4. Each $P_i$ waits to receive $\mathit{sid}_j$ from every participant $P_j$

5. Each $P_i$ computes the hash $\mathit{sid} \gets H_1(\mathit{sid}_1, \cdots \mathit{sid}_N)$

6. Each $P_i$ generates a random polynomial $f_i$ of degree $\mathsf{max\textit{\_}malicious}$.

<font color="orange">

$\quad$ ++ Each $P_i$ computes the following:

* If $P_i\notin \mathit{old\textit{\_}signers}$ then set $f_i(0) \gets 0$

* Else set $f_i(0) \gets \lambda_i(I) \cdot \mathit{old\textit{\_}sk}$

</font>

7. Each $P_i$ generates a commitment of the polynomial $C_i \gets f_i \cdot G$ (commits every coefficient of the polynomial).

8. Each $P_i$ generates a hash $h_i \gets H_2(i, C_i, \mathit{sid})$

9. Each $P_i$ picks a random nonce $k_i$ and computes $R_i \gets k_i \cdot G$

10. Each $P_i$ computes the Schnorr challenge $c_i \gets H_3(\mathit{sid}, i, C_i(0), R_i)$

11. Each $P_i$ computes the proof $s_i \gets k_i + f_i(0) \cdot c_i$

12. Each $P_i$ sends $h_i$ to every participant

**Round 3:**

13. Each $P_i$ waits to receive $h_i$ from every participant $P_j$.

14. Each $P_i$ reliably broadcasts $(C_i, R_i, s_i)$.

**Round 4:**

15. Each $P_i$ waits to receive $(C_j, \pi_j)$ from every participant $P_j$.

16. Each $P_i$ computes: $\forall j\in\set{1, \cdots N}, \quad c_j \gets H_3(\mathit{sid}, j, C_j(0), R_j)$.

17. Each $P_i$ asserts that: $\forall j\in\set{1, \cdots N}, \quad R_j = s_i \cdot G - c_j \cdot C_j(0)$.

18. Each $P_i$ asserts that: $\forall j\in\set{1, \cdots N}, \quad h_j = H_2(j, C_j, \mathit{sid})$.

19. $\textcolor{red}{\star}$ Each $P_i$ **privately** sends the evaluation $f_i(j)$ to every participant $P_j$.

**Round 5:**

20. Each $P_i$ waits to receive $f_j(i)$ from every participant $P_j$.

21. Each $P_i$ asserts that: $\forall j\in\set{1, \cdots N}, \quad f_j(i) \cdot G = \sum_m j^m \cdot C_j[m]$ where $C_j[m]$ denotes the m-th coefficient of $C_j$.

22. Each $P_i$ computes its private share $\mathit{sk}_i \gets \sum_j f_j(i)$.

23. Each $P_i$ computes the master public key $\mathit{pk} \gets \sum_j C_j(0)$.

<font color="orange">

$\quad$ ++ Each $P_i$ asserts that $\mathit{pk} = \mathit{old\textit{\_}pk}$

</font>

24. Each $P_i$ reliably broadcasts $\mathsf{success_i}$.

**Round 5.5:**

25. Each $P_i$ waits to receive $\mathsf{success_j}$ from every participant $P_j$.

**Output:** the keypair $(\mathit{sk}_i, \mathit{pk})$.


### Key Refresh

A key refresh protocol is a special case of the key resharing where $\mathit{old\textit{\_}signers} = \set{P_1, \ldots P_N}$ and where $\mathit{old\textit{\_}max\textit{\_}malicious} = \mathit{max\textit{\_}malicious}$