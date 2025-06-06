This is an amended version Robust ECDSA scheme of \[[DJNPO](https://eprint.iacr.org/2020/501.pdf)\].
The amendment does away with several checks that the scheme requires to happen and thus dropping the security from active adversaries (under honest majority assumption) to honest-but-curious adversaries.

This implementation is meant to be integrated to a Trusted Execution Environement (TEE) which is meant prevent an adversary from deviating from the protocol. Additionally, the communication between the parties is assumed to be encrypted under secret keys integrated into the TEE.


## ATTENTION:
Some papers define the number of malicious parties (eg this exact paper) to be the same as the threshold.
Other papers seem to define the number of malicious parties to be threshold - 1.

The first case corresponds to robust ecdsa implementation. (explicit condition on the threshold eg n >= 3t + 1)
The second case corresponds to the ot-based ecdsa implementation. (no explicit condition e.g. n >= t)

CARE TO UNIFY THE IMPLEMENTATION such as number of malicious parties = threshold. Discuss with the team such duality!
