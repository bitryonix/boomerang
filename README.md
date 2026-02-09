# Proof of Concept Implementation for Boomerang: Bitcoin Cold Storage With Built-in Coercion Resistance

Boomerang is a bitcoin cold storage protocol that provides coercion resistance via a non-deterministic withdrawal mechanism, interweaved with duress checks.
This is the proof-of-concept (POC) implementation of boomerang protocol. All entities are written in rust.
For more info on the design please refer to [boomerang design repo](https://github.com/bitryonix/boomerang_design).

## Table of Contents

- [Proof of Concept Implementation for Boomerang: Bitcoin Cold Storage With Built-in Coercion Resistance](#proof-of-concept-implementation-for-boomerang-bitcoin-cold-storage-with-built-in-coercion-resistance)
  - [Table of Contents](#table-of-contents)
  - [Setup and withdrawal steps](#setup-and-withdrawal-steps)
  - [Run](#run)
  - [Architecture](#architecture)
  - [Roadmap](#roadmap)

## Setup and withdrawal steps

All steps are laid out clearly in [setup.rs](poc/src/setup.rs) and [withdrawal.rs](poc/src/withdrawal.rs) files, exactly following the design message diagrams of [setup](https://github.com/bitryonix/boomerang_design/blob/main/setup/setup_diagram_without_states.svg), [initiator withdrawal](https://github.com/bitryonix/boomerang_design/blob/main/withdrawal/initiator_withdrawal_diagram_without_states.svg) and [non-initiator withdrawal](https://github.com/bitryonix/boomerang_design/blob/main/withdrawal/non_initiator_withdrawal_diagram_without_states.svg) design files.  

## Run

We have tested and ran this code on linux and mac.

```bash
cargo run --bin poc
```

## Architecture

Decisions on the architecture of the POC, are documented in the [Architecture.md file](Architecture.md).

## Roadmap

- [x] Writing the POC in rust.
- [ ] Dynamic simulation of the protocol to optimize parameters, given delays and non-linearity.
- [ ] Implementing the java card applet (Boomlet).
- [ ] Observing and deciding if java card can handle the expectations.
- [ ] Implementing the ST software and hardware.
- [ ] Implementing ancillaries.
- [ ] Implementing network layer.
- [ ] Implementing proper error handling and fallback scenarios.
- [ ] Adding networking and CLI to the code.
- [ ] Adding GUI.
