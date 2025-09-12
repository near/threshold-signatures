This document specifies the signing protocol described in [[DJNPO20](https://eprint.iacr.org/2020/501)].
The protocol is split into two phases, a pre-signing phase and a signing phase.

*Note that We slightly modify the original scheme and push parts of the computation done on the signing phase to the presigning phase to improve the performance of the former phase. Additionally, the authors assume the message is an input to the first round, but their proof does not require it until the last round.
We highlight in red the difference between our scheme and the original one.*


# Presigning

In this phase, a set of parties $\mathcal{P}_ 1 \subseteq \mathcal{P}_ 0$
of size $N_1 \geq t$ wishes to generate a threshold $t' = t$ sharing
of a pre-signature.



Round 0 (Offline):
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

Round 1 (Offline):
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
20. Store locally alpha_i, beta_i
The original paper pushes parts of the computations in the previous lines to the signing round. We do not do so to reduce the computation time in the online phase
21. [(Local) Output of Round 2.5] Store R


Round 3 (Online): input is m (message)
23. [Output of Round 3]
Each party outputs its signature share s_i = alpha_i * m + beta_i
The original paper performs si = hi(m + r*xi) + ci where ci = m*di + ei
But we thought it is better to perform the following (computation-wise):
si = hi * m  + r*xi*hi + m*di + ei
   = m* (hi+di) + (r*xi*hi  + ei)
   = m * alpha_i + beta_i
24. Send s_i

Combine (Online):
25. Interpolate s = interpolate(s_1,..., s_2t+1; 0):= SUM_i s_i lambda_i
Abort if s=?= 0
26. Normalize s  as s := abs(s)
27. Check Verify(pk, m , (R,s))
28. Return (R, s)
