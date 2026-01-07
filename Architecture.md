# Architecture

This document is produced to help you understand the decisions that implementation has made on how to handle certain issues and implement certain features. This does not cover the logic of Boomerang protocol itself.

## Logging

Implementation uses `tracing` crate for logging. The `tracing_utils` crate contains macros for assertion/unwrapping + logging functionalities, and developers must only use `tracing` indirectly through this crate.

Panics are all logged with ERROR log level.

## Protocol Structures

Boomerang uses several structs that are accessed by more than one entity: Structs that are shared between entities and do not belong to a single one. The `protocol` crate accommodates these structures. These structures are divided into two categories:

### Messages

These are protocol-level messages that are passed between entities (each must be produced by one and consumed by the other). Messages only implement minimal logic related to their creation and an `into_parts()` method that consumes the caller and returns its disintegrated fields in a tuple. `into_parts()` is used by the consumer of the message to take ownership of its content. Messages must implement `Message` trait. Empty messages have an exemption from `new_without_default` clippy rule, because default does not make sense for a message struct and no other non-empty message implements it.

### Constructs

Certain structs are used in multiple places (e.g. `PeerId`). These are placed under constructs section of `protocol` crate. They are only allowed to have a minimal self-contained logic implemented in them.

## Cryptography

The `cryptography` crate standardizes the cryptographic primitives used through the protocol. This includes hashing, signatures, symmetric encryption/decryption, and more. Other crates must perform cryptographic operations only through the `cryptography` crate.

## Message Passing

Boomerang protocol works with a message-in-message-out rule: Each entity that receives message(s), produces message(s) to other entities, and only engages in message production if it receives the message(s) it expects. In code, entities have `produce_*` and `consume_*` methods that produce and consume protocol-level messages. `consume_*` methods change the inner state of entities, therefore all of them borrow the entity mutably, while `produce_*` methods only produce messages for other entities and do not mutate the state of entities, therefore they borrow entities immutably. The decision to differentiate between consume and produce methods as opposed to having a single consume+produce method was made to make the future implementations of retrying and failure recovery easier.

`consume_*` and `produce_*` methods create `tracing` spans using `instrument` macro. These methods emit log events in following scenarios:

- Start of the method (TRACE log level)
- Finish of the method along with its result (TRACE log level)
- An error happening (WARN log level)

The flow of a `consume_*` method is as follows (sections are clearly delineated by comments in code):

- Log start
- Check state
- Unpack message data
- Unpack state data
- Do computation
- Change state
- Log finish

Even if a section of this is not applicable to a certain `consume_*` method, it still must be present and have a `{}` code in its place. `produce_*` methods follow a mostly similar flow of execution:

- Log start
- Check state
- Unpack state data
- Do computation
- Log finish
