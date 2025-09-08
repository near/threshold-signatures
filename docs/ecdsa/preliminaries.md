This document specifies how the original ECDSA works and
The protocol is split into two main phases, a pre-signing phase

# Preliminaries

Let $\mathbb{G}$ be a finite group, with generator $G$, of prime order $q$.

Let $\text{Hash} : \\{0, 1\\}^* \to \mathbb{F}_q$ denote a hash function used for hashing messages
for signatures.
Let $h : \mathbb{G} \to \mathbb{F}_q$ denote a different "hash function" used for converting points to scalars.
Commonly, this is done by "simply" taking the x coordinate of the affine
representation of a point.
Let $H : \\{0, 1\\}^* \to \\{0, 1\\}^{2\lambda}$ be a generic hash function.

# ECDSA Recap

ECDSA is defined by algorithms for key generation, signing, and verification:

First, key generation:

$$
\begin{aligned}
&\underline{\texttt{Gen}}:\cr
&\ x \xleftarrow{\$} \mathbb{F}_q\cr
&\ X \gets x \cdot G\cr
&\ \texttt{return } (x, X)\cr
\end{aligned}
$$

Next, signing a message $m \in \{0, 1\}^*$:

$$
\begin{aligned}
&\underline{\texttt{Sign}(x, m)}:\cr
&\ k \xleftarrow{\$} \mathbb{F}_q\cr
&\ R \gets \frac{1}{k} \cdot G\cr
&\ r \gets h(R)\cr
&\ \texttt{retry if } r = 0\cr
&\ s \gets k (\mathsf{H}(m) + rx)\cr
&\ \texttt{return } (R, s)
\end{aligned}
$$

Note that we deviate slightly from ECDSA specifications by returning
the entire point $R$ instead of just $r$.
This makes it easier for downstream implementations to massage
the result signature into whatever format they need for compatability.
Also, the t


Finally, verification:

$$
\begin{aligned}
&\underline{\texttt{Verify}(X : \mathbb{G}, m : \{0, 1\}^*, (R, s) : \mathbb{G} \times \mathbb{F}_q):}\cr
&\ r \gets h(R)\cr
&\ \texttt{assert } r \neq 0, s \neq 0\cr
&\ \hat{R} \gets \frac{\texttt{Hash}(m)}{s} \cdot G + \frac{r}{s} \cdot X\cr
&\ \texttt{asssert } \hat{R} = R\cr
\end{aligned}
$$
