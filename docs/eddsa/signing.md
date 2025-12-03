This document specifies the distributed EdDSA signing protocol called FROST.
The implementation is heavily inspired by the Zcash  Foundation
[implementation](https://github.com/ZcashFoundation/frost) and builds the
scheme on top of Curve25519. The implementation thus generates signatures
that can be checked by and Ed25519 verifier.
We implement the two round FROST protocol without the extra round responsible
of detecting which party deviated from the protocol.

Currently, the protocol runs in a single online phase, however, we intend to
make each of the two round run respectively in an offline phase and an
online phase. This helps improving the performance of the online phase
and serve the users even faster.

### Note: the threshold $t =$ *number_malicious_parties*

# Signing

In this phase, a set of parties $\mathcal{P}_1 \subseteq \mathcal{P}_0$
of size $N_1 > t$ wishes to generate an EdDSA signature.

The inputs to this phase are:
1) The secret key share $x_i$.
2) The public key $X$
5) The message hash $h= H(m)$

**Round 1:**

1. Each $P_i$ commits to its secret share $x_i$ following the
[RFC9591](https://datatracker.ietf.org/doc/html/rfc9591#name-round-one-commitment) standards. In short, the following cryptographic steps happen:
* Pick two $32$ bytes strings uniformly at random $s_1$ and $s_2$
* Compute the nonces  $a_i \gets H(s_1, x_i); \quad b_i \gets H(s_2, x_i)$
* Compute the points $A_i\gets a \cdot G; \quad B_i\gets b \cdot G$
2. $\star$ Each $P_i$ sends $(A_i, B_i)$ **only to the coordinator**.

**Round 1 (Coordinator):**

3. $\bullet$ The coordinator waits to receive $(A_j, B_j)$ from every party.
4. $\star$ The coordinator relays all collected terms $(A_j, B_j)$ to every other participant

**Round 2:**