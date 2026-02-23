# Protocol Execution Framework (`src/protocol/`)

This module provides the infrastructure for defining and running multi-party protocols as message-driven state machines.

## Core Abstraction

### `Protocol` trait (`mod.rs`)

All threshold protocols in this library implement the `Protocol` trait:

```rust
pub trait Protocol {
    type Output;
    fn poke(&mut self) -> Result<Action<Self::Output>, ProtocolError>;
    fn message(&mut self, from: Participant, data: MessageData);
}
```

External consumers drive protocols by:
1. Calling `poke()` repeatedly to get the next `Action` (send a message, wait, or return the final result)
2. Calling `message(from, data)` to deliver incoming messages from other participants

The `Action` enum maps directly to the network layer primitives:
- `SendMany(data)` -- broadcast to all other participants
- `SendPrivate(participant, data)` -- encrypted point-to-point message
- `Wait` -- no progress until a new message arrives
- `Return(value)` -- protocol completed

### Async-to-State-Machine Adapter (`internal.rs`)

Protocol logic is written as ergonomic `async fn` code using channels:

- **`SharedChannel`** -- broadcast communication (send to all, receive from specific participant at a waitpoint)
- **`PrivateChannel`** -- point-to-point encrypted communication
- **`Waitpoint`** -- round counter separating protocol phases

The `make_protocol(comms, future)` function converts an async future into a `Protocol` implementation by polling it cooperatively without requiring a tokio or other async runtime. Messages are serialized with MessagePack (`rmp_serde`) and prefixed with SHA-256-derived headers for channel multiplexing.

### Echo Broadcast (`echo_broadcast.rs`)

Implements Authenticated Double-Echo Broadcast (Byzantine Reliable Broadcast) following \[CGR\]:

```
Phase 1: SEND   -- sender broadcasts initial value
Phase 2: ECHO   -- all parties echo what they received
Phase 3: READY  -- parties signal readiness after sufficient echoes
```

This provides reliable delivery guarantees even with up to `floor((N-1)/3)` malicious parties. Used exclusively in DKG rounds 1, 3, and 5.5 for commitment and share broadcasting.

### Helpers (`helpers.rs`)

`recv_from_others` -- waits for exactly one message from each other participant at a given waitpoint. Used in virtually every protocol round that collects contributions.

## How Protocols Are Defined

Every protocol constructor follows the same pattern:

1. Validate inputs, return `InitializationError` on failure
2. Create a `Comms` instance
3. Write the protocol logic as an `async fn` using the channels from `Comms`
4. Wrap with `make_protocol(comms, future)` to get an `impl Protocol`

## Further Reading

- [`docs/network_layer.md`](../../docs/network_layer.md) -- formal specification of the communication model, channel types, and the echo broadcast protocol
- [`docs/dkg.md`](../../docs/dkg.md) -- the DKG protocol that most heavily uses echo broadcast
