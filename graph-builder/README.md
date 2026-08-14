# circom-witness-graph-builder

This crate compiles Circom 2.2.2 circuits and emits optimized graph files for the MIT-licensed `circom-witness-rs` runtime crate.

It links directly to Circom's compiler crates and is therefore distributed under `GPL-3.0-only`. Runtime applications do not need this crate: generate `graph.bin` as a one-off build artifact, then embed it using `circom-witness-rs`.

The builder keeps statically traceable witness work in the optimized graph and embeds portable
Circom IR for input-dependent function control flow or array indexes. Dynamic local template
branches are lowered to arithmetic selects.

```shell
cargo run --release -p circom-witness-graph-builder -- circuit.circom graph.bin
```

An optional third and subsequent argument supplies Circom library search paths.
Pass `--O1` before the circuit when its reference R1CS/WTNS was compiled with O1; O2 remains the
default.
