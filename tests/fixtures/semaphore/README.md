# Semaphore test circuit

These Circom sources are copied verbatim from
[`philsippl/semaphore-witness-example`](https://github.com/philsippl/semaphore-witness-example)
at commit `c83d277c2c71bb68971413bf768c8d7397e5e331`.

The end-to-end test compiles `semaphore.circom` to WASM with Circom, builds the
latest optimized `circom-witness-rs` graph directly from Circom's typed witness
IR, and loads `graph-v0.3.0.bin`, which was built by the `v0.3.0` tag through its
historical C++ tracing pipeline. It compares every witness element from both
graphs with the Circom WASM witness.

The legacy fixture was generated with Circom 2.2.2 from the circuit in this
directory. Its SHA-256 is
`953afad5359f06fea34957349d51117150e3f3f3bbac0dc2f49cae8ded8312d1`.

Run it with Circom 2.2.2 and Node.js available:

```console
cargo test --release --features test-semaphore --test semaphore_witness
```

Set `CIRCOM` or `NODE` when either executable is not on `PATH`.
