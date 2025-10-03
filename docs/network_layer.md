# Protocol Communication Layer

This document outlines the communication layer for our multi-party computation (MPC) protocols, covering its assumptions, functions, and documentation notation.

## Core Assumptions

Our protocols operate on two fundamental assumptions about the network channels:

- **Authenticated Channels:** All messages are sent over authenticated channels. Senders' identities are always verifiable.
- **Confidentiality for Private Messages:** Channels used for private messages (`send_private`) must be encrypted.

<details>
  <summary>Practical Implementation</summary>
  In practice, we satisfy both requirements by running all protocols over a network where participants are connected via a TLS channel. This ensures both, authentication and confidentiality.
</details>

## Communication Primitives

The protocol implementation provides several communication primitives:

- **`send_many`**: Sends a message to participants except the sender itself. This is a peer-to-peer sending with no security guarantees used by one sender in destination to multiple receiver.

- **`send_private`**: Sends a message to a single, specific participant. The underlying channel is assumed to be confidential.

- **Byzantine Reliable Broadcast (`echo_broadcast`)**: A complex protocol that ensures all honest participants agree on the same message, even in the presence of Byzantine faults. The protocol guarantees:

  - **Validity**: If a correct process `p` broadcasts `a` message `m`, then `p` eventually delivers `m`.
  
  - **No duplication**: No message is delivered more than once.
  
  - **No creation**: If a process delivers a message `m` with sender `s`, then m was previously broadcast by process `s`.

  - **Agreement**: If a message `m` is delivered by some correct process, then `m` is eventually delivered by every correct process.

  - **Totality**: If some message is delivered by any correct process, then every correct process eventually delivers some message.

These guarantees hold under standard _threshold assumptions_ (where `n` = _total participants_, `f` = _maximum faulty nodes tolerated_):
   - **DKG**: Threshold `t = f + 1`. Requires `f ≤ ⌊N/3⌋`. Example: with `n = 7`, `f = 2` -> `t = 3`.

   - **OtBasedECDSA**: Threshold `t = f + 1`. No additional requirement. Example: with `n = 7`, `f = 2` -> `t = 3`.
   
   - **Robust ECDSA**: Threshold `t = f`. Requires `2f + 1 ≤ N`. Example: with `n = 7`, `f = 2` -> `t = 2`.
