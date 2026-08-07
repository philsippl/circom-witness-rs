# Semaphore test circuit

These Circom sources are copied verbatim from
[`philsippl/semaphore-witness-example`](https://github.com/philsippl/semaphore-witness-example)
at commit `c83d277c2c71bb68971413bf768c8d7397e5e331`.

The end-to-end test compiles `semaphore.circom` to both C++ and WASM with Circom,
builds the optimized `circom-witness-rs` graph from the C++ generator, executes
both witness generators with the example input, and compares every witness
element in order.

Run it with Circom 2.2.2 and Node.js available:

```console
cargo test --release --features test-semaphore --test semaphore_witness
```

Set `CIRCOM` or `NODE` when either executable is not on `PATH`.
