# Distribute Key Generation

We define a variant of the two-round DKG protocol PedPop \[[KG](https://eprint.iacr.org/2020/852.pdf)\].
Our variant, PedPop+ is less efficient, but achieves a notion of simulatability with aborts,
a stronger notion of security than the one promised by plain PedPop.

PedPop+ is a four rounds protocol and makes use of a reliable broadcast channel, each of which is a 3 round protocol,
making the total number of rounds 12. The broadcast channel is implemented in `src/protocol/echo_broadcast.rs`.

The implemented DKG serves as a generic one that can be used with multiple different underlying elliptic curves. We thus use it with `Secp256k1` for ECDSA schemes, `Curve25519` for EdDSA scheme, and `BLS12_381` for the confidential key derivation functionality.

## Keygen, Reshare and Refresh

The core of the dkg protocol is implemented in a subfunction called `do_keyshare` and serves for three applications:

* Key generation: denoted in the implementation with `keygen`. It allows a set of parties to jointly generate from scratch a private key share each and a master public key. The master public key should be common for all the participants and should reflect each of the private shares.

* Key resharing: denoted in the implementation with `reshare`. It allows for a set of participants who already own valid private shares to kick away other participants from the pool, create fresh shares for new participants i.e. new joiners to the pool, and/or change the **cryptographic threshold** a.k.a. *the reconstruction threshold* described in section [Types of Thresholds](#types-of-thresholds).

* Key refresh: denoted in the implementation with `refresh`. It is a special case of the key resharing in which the set of participants stays the same before and after the protocol run and with no changes to the crypto. The goal being that each participant would refresh their signing share without modifying the master public key.

## Types of Thresholds

Talk about the distributed systems threshold and the reconstruction cryptography threshold.



### Ideas

Never use the word threshold again! Or use a very well defined definition for it so you can say, the cryptographic threshold or the distributed systems threshold.

max_faulty: {invariant} {unchangeable} faulty nodes (async distributed systems) at most one third of participants

max_malicious: the maximal accepted number of participants for the cryptography part, i.e. assuming perfect reliable broadcast channels.

reconstruction_threshold: for the cryptographic threshold a.k.a. the reconstruction threshold it is always equals to max_malicious + 1

min_active_participants: number of necessary active participants to generate a valid signature


### More Ideas

Discuss the Echo Broadcast Protocol in a different issue for networking.

Add a readme in every folder to link to the actual documentations

Talk about the algorithm

Talk about the unaccepted corner cases with thresholds and number of participants etc...

Speak of non-Robustness?
