# Boomerang: A Bitcoin Cold Storage with Duress Protection [Proof of Concept implementation]

Boomerang is a bitcoin cold storage protocol that provides duress protection via a non-deterministic withdrawal mechanism, interweaved with duress checks.
This is the proof-of-concept (POC) implementation of boomerang protocol. All entities are written in rust.
For more info on the design please refer to [boomerang design repo](https://github.com/bitryonix/boomerang_design)

## Run

We have tested and ran this code on linux and mac.

```bash
cargo run --bin poc
```

## Roadmap

- [x] Writing the POC in rust.
- [ ] Dynamic simulation of the protocol to optimize parameters, given delays and non-linearity.
- [ ] Implementing the java card applet (boomlet).
- [ ] Implementing the ST software and hardware.
- [ ] Implementing ancillaries.
- [ ] Implementing network layer.
- [ ] Implementing proper error handling.
- [ ] Adding networking and CLI to the code.
- [ ] Adding GUI.
