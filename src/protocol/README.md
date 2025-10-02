# Protocol Communication Layer

This document outlines the communication layer for our multi-party computation (MPC) protocols, covering its assumptions, functions, and documentation notation.

## Core Assumptions

Our protocols operate on two fundamental assumptions about the network channels:

- **Authenticated Channels:** All messages are sent over authenticated channels. Senders' identities are always verifiable.
- **Confidentiality for Private Messages:** Channels used for private messages (`send_private`) must be encrypted.

<details>
  <summary>Practical Implementation</summary>
  In practice, we satisfy both requirements by running all protocols over a network where each participant is connected via a TLS channel with a certified key pair. This ensures all communication is both authenticated and encrypted.
</details>

## Communication Primitives

The protocol implementation provides several communication primitives:

- **`send_many`**: Sends a message to all other participants. This is a basic, non-blocking broadcast that does not guarantee message delivery or ordering. It's suitable for rounds where eventual delivery is sufficient.

- **`send_private`**: Sends a message to a single, specific participant. The underlying channel is assumed to be confidential.

- **Reliable Broadcast (`echo_broadcast`)**: A higher-level protocol that ensures all honest participants agree on the same set of messages from senders. It is built using `send_many` and guarantees that a message is delivered if and only if all honest parties receive it. This is critical for rounds requiring consensus.

## Documentation Notation

In our protocol specifications (particularly for ECDSA), we use the following symbols to describe actions:

| Symbol | Meaning | Description |
| :---: | :--- | :--- |
| `⋆` | **Send** | A participant sends a message to one or more others. |
| `⚫` | **Receive** | A participant waits to receive a message. |
| `🔺` | **Assert** | A participant makes an assertion. The protocol aborts if it fails. |
| `textcolor{red}{\star}` | **Send Private** | A participant sends a private, encrypted message. |

