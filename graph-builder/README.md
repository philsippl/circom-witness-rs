# circom-witness-graph-builder

This crate compiles Circom 2.2.2 circuits and emits optimized graph files for the MIT-licensed `circom-witness-rs` runtime crate.

It links directly to Circom's compiler crates and is therefore distributed under `GPL-3.0-only`. Runtime applications do not need this crate: generate `graph.bin` as a one-off build artifact, then embed it using `circom-witness-rs`.

```shell
cargo run --release -p circom-witness-graph-builder -- circuit.circom graph.bin
```

An optional third and subsequent argument supplies Circom library search paths.
