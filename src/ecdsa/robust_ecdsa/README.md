This is an amended version Robust ECDSA scheme of \[[DJNPO](https://eprint.iacr.org/2020/501.pdf)\].
The amendment does away with several checks that the scheme requires to happen and thus dropping the security from active adversaries (under honest majority assumption) to honest-but-curious adversaries.

This implementation is meant to be integrated to a Trusted Execution Environement (TEE) which is meant prevent an adversary from deviating from the protocol. Additionally, the communication between the parties is assumed to be encrypted under secret keys integrated into the TEE.