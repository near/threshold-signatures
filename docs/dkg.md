# Distribute Key Generation

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

The BFT threshold states that the maximum number of faulty nodes a distributed system ($\mathsf{max\_faulty}$) can tolerate while still reaching consensus is at most one-third of the total number of participants $N$. More specifically:
$$\mathsf{max\_faulty} \leq \frac{N - 1}{3}$$

The cryptography threshold refers to the maximum number of necessay malicious parties ($\mathsf{max\_malicious}$) a certain scheme can handle without compromising on the security and assuming the existance of an underlying reliable broadcast channel. $\mathsf{max\_malicious}$ is scheme dependent and can have a different value than $\mathsf{max\_faulty}$. For instance, in the OT based ECDSA, $\mathsf{max\_malicious}$ can be up to $N-1$, but in Robust ECDSA scheme $\mathsf{max\_malicious}$ must not exceed $\frac{N - 1}{3}$.

### DKG and thresholds

Due to the fact that PedPop+ utilizes reliable broadcast channel to securely generate private shares, it thus lies on the edge between the asynchronous distributed systems and cryptography. For this reason, we set
$\mathsf{max\_faulty} = \frac{N - 1}{3}$ as an invariable parameter and allow our key generation and key resharing protocols to fix/modify only the $\mathsf{max\_malicious}$ threshold depending on the scheme requirements and on the library user's choice.

## Technical Details

Let $P_1, \cdots P_N$ be $N$ different participants, and $\mathsf{max\_malicious}$ be the desired cryptography threshold. Let $H_1, H_2, H_3$ be domain separated hash functions.

### Key Generation

We define PedPop+ key generation as follows:

**Round 1:**

1. Each $P_i$ generates a random 32-byte sesssion identifier $\mathit{sid}_i$

2. Each $P_i$ reliably broadcasts $\mathit{sid}_i$

**Round 2:**

3. Each $P_i$ waits to receive $\mathit{sid}_j$ from every participant $P_j$

4. Each $P_i$ computes the hash $\mathit{sid} \gets H_1(\mathit{sid}_1, \cdots \mathit{sid}_N)$

5. Each $P_i$ generates a random polynomial $f_i$ of degree $\mathsf{max\_malicious}$.

6. Each $P_i$ generates a commitment of the polynomial $C_i \gets f_i \cdot G$ (commits every coefficient of the polynomial).

7. Each $P_i$ generates a hash $h_i \gets H_2(i, C_i, \mathit{sid})$

8. Each $P_i$ picks a random nonce $k_i$ and computes $R_i \gets k_i \cdot G$

9. Each $P_i$ computes the Schnorr challenge $c_i \gets H_3(\mathit{sid}, i, C_i(0), R_i)$

10. Each $P_i$ computes the proof $s_i \gets k_i + f_i(0) \cdot c_i$

11. Each $P_i$ sends $h_i$ to every participant

**Round 3:**

12. Each $P_i$ waits to receive $h_i$ from every participant $P_j$.

13. Each $P_i$ reliably broadcasts $(C_i, R_i, s_i)$.

**Round 4:**

14. Each $P_i$ waits to receive $(C_j, \pi_j)$ from every participant $P_j$.

15. Each $P_i$ computes: $\forall j\in\set{1, \cdots N}, \quad c_j \gets H_3(\mathit{sid}, j, C_j(0), R_j)$.

16. Each $P_i$ asserts that: $\forall j\in\set{1, \cdots N}, \quad R_j = s_i \cdot G - c_j \cdot C_j(0)$.

17. Each $P_i$ asserts that: $\forall j\in\set{1, \cdots N}, \quad h_j = H_2(j, C_j, \mathit{sid})$.

18. $\textcolor{red}{\star}$ Each $P_i$ **privately** sends the evaluation $f_i(j)$ to every participant $P_j$.

**Round 5:**

19. Each $P_i$ waits to receive $f_j(i)$ from every participant $P_j$.

20. Each $P_i$ asserts that: $\forall j\in\set{1, \cdots N}, \quad f_j(i) \cdot G = \sum_m j^m \cdot C_j[m]$ where $C_j[m]$ denotes the m-th coefficient of $C_j$.

21. Each $P_i$ computes its private share $\mathit{sk}_i \gets \sum_j f_j(i)$.

22. Each $P_i$ computes the master public key $\mathit{pk} \gets \sum_j C_j(0)$.

23. Each $P_i$ reliably broadcasts $\mathsf{success_i}$.


**Round 5.5:**

24. Each $P_i$ waits to receive $\mathsf{success_j}$ from every participant $P_j$.

**Output:** the keypair $(\mathit{sk}_i, \mathit{pk})$.
