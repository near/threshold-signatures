This document specifies the signing protocol described in [[DJNPO20](https://eprint.iacr.org/2020/501)].
The protocol is split into two phases, a pre-signing phase and a signing phase.

*Note that We slightly modify the original scheme and push parts of the computation done on the signing phase to the presigning phase to improve the performance of the former phase. Additionally, the authors assume the message is an input to the first round, but their proof does not require it until the last round.
We highlight in red the difference between our scheme and the original one.*


# Presigning

In this phase, a set of parties $\mathcal{P}_ 1 \subseteq \mathcal{P}_ 0$
of size $N_1 \geq t$ wishes to generate a threshold $t' = t$ sharing
of a pre-signature.

The inputs to this phase are:

1) The secret key share $x_i$.


**Round 1:**

Generate a random secret sharing of a scalar [k],
Each party samples a random degree t polynomial fk_i (where the group nonce k = SUM fk_i(0)).
Generate a second random secret sharing of a scalar [a]
Similarly, each party samples a degree t random polynomial fa_i (where a = SUM fa_i(0)).
Compute [b] = ZSS(2t), a zero secret sharing of degree 2t
Compute [d] = ZSS(2t), a zero secret sharing of degree 2t
Compute [e] = ZSS(2t), a zero secret sharing of degree 2t
[Output of Round 0]
Privately send all other parties their share (k_ij, a_ij, b_ij, d_ij, e_ij)
	We use notation fa_i(j) := a_ij and analogously for the rest of the terms.

**Round 2:**

Compute 	k_i = SUM_j k_ij	 a_i = SUM_j a_ij
			b_i = SUM_j b_ij	 d_i = SUM_j d_ij	e_i = SUM_j e_ij;
In this step, each party sums shares received from all other parties.

Compute R_i = g^{k_i}
      9. Compute [w] = [a][k]
Each party computes w_i = a_i * k_i + b_i, where b_i is a blinding factor due to the fact that a_i * k_i is not necessarily random
     10. [Output of Round 1] Send (in the clear) R_i, w_i,

Round 2 (Offline): Computational overhead: Requires one poly interpolation and (n-t)  exponent interpolations
11. For j from t+2 … n:
Check ExponentInterpolation(R1, … ,R_{t+1}; j) =?=  Rj
13. Compute R = ExponentInterpolation(R1,.., R_{t+1}; 0)
Abort if R =?= Identity
            14. Compute W_i = R^{a_i}
15. [Output of Round 2] Send (in the clear) W_i

Round 2.5: Computational overhead: Requires one poly interpolation and (n-t)  exponent interpolations
16. For j from t+2 … n:
Check ExponentInterpolation(W1, … ,W_{t+1}; j) =?=  Wj
17. Compute W = ExponentInterpolation(W1, …, W_{t+1})
Check W =?= g^w
      	18. Derive w
Each party performs polynomial interpolation (of degree 2t) to derive w as in w = interpolate(w_1,..,w_2t+1; 0) := \SUM_i w_i lambda_i .
In the paper, this operation is defined as the protocol w ← WMULOPEN([a], [k]; [b]).
“W” stands for weak, since any misbehaving party that deviates from the protocol can cause the protocol to output an invalid “w.” The authors then define a consistency check to ensure that the correct w is output. However, in the honest but curious setting, we can omit this check.
Abort if w =?= 0
      	19. Each party can then compute [k^-1] locally as [a] * w^-1
Let h_i be each party’s share of [k^-1] e.g. h_i = a_i * w^{-1}
     	20. Compute Rx = x-coordinate(R)
21. Let alpha_i = h_i+d_i
22. Let beta_i = h_i * Rx * x_i + e_i

**Output:** the presignature $(R, \alpha_i, \beta_i)$.

# Signing

In this phase, a set of parties $\mathcal{P}_2 \subseteq \mathcal{P}_ 1$
of size $N_2 \geq t$ wishes to generate an ECDSA signature.

The inputs to this phase are:
1) The presignature $(R, \alpha_i, \beta_i)$,
2) The public key $X$
3) A "fresh" public source of entropy $\rho$
4) A tweak $\epsilon$ used during key derivation
5) The message hash $h= H(m)$

**Rerandomization & Key Derivation:**

???????????????????????????????????????????????????????
1. Each $P_i$ derives a randomness $\delta = \mathsf{HKDF}(X, h, R, \rho)$
2. Each $P_i$ rerandomizes the following elements:

    * $R  \gets R^\delta$
    * $\sigma_i \gets (\sigma_i + \epsilon \cdot k_i) \cdot \delta^{-1}$
    * $k_i \gets k_i \cdot \delta^{-1}$

???????????????????????????????????????????????????????

**Round 1:**

1. Each $P_i$ computes its signature share $s_i = \alpha_i * h + \beta_i$
2. $\star$ Each $P_i$ sends $s_i$ to every other party.
3. $\bullet$ Each $P_i$ waits to receive $s_j$ from every other party.
4. Each $P_i$ sets $s \gets \sum_{j \in [N]} \lambda(\mathcal{P}_2)_j \cdot s_j$.
5. $\blacktriangle$ Each $P_i$ *asserts* that $s\neq 0$
6. Perform the low-S normalization, i.e. $s \gets -s $ if $s\in\\{\frac{q}{2}..~q-1\\}$
7. $\blacktriangle$ Each $P_i$ asserts that $(R, s)$ is a valid ECDSA signature for $h$.

**Output:** the signature $(R, s)$.






## Differences with [[DJNPO20](https://eprint.iacr.org/2020/501)]

Rerandomization,


The original paper pushes parts of the presignature computations in the previous lines to the signing round. We do not do so to reduce the computation time in the online phase


The original paper performs si = hi(m + r*xi) + ci where ci = m*di + ei
But we thought it is better to perform the following (computation-wise):
si = hi * m  + r*xi*hi + m*di + ei
   = m* (hi+di) + (r*xi*hi  + ei)
   = m * alpha_i + beta_i
