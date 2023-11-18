# 🏎️ circom-witness-rs

## Description

This crate provides a fast witness generator for circom circuits. It serves as a drop-in replacement for circom's witness generator. It was created because the wasm generator from circom is very slow for larger circuits and also requires a wasm runtime (which can be painful sometimes). The native c++ generator is faster but relies on x86 assembly for field operations, which makes it rather impossible to use on other platforms (e.g. to be cross-compiled to arm to be used on mobile devices).

The crate comes with two modes:

1. Generate the static execution graph required for the witness generation at build time (`--features=build-witness`).
2. Generate the witness elements at runtime.

In the first mode, it generates the c++ version of the witness generator through circom and links itself against it. The c++ code is made accessible to rust through [`cxx`](https://github.com/dtolnay/cxx). It hooks all field functions (which are x86 asm in the original generator), such that it can recreate the execution graph through symblic execution. The execution graph is further optimized through constant propagation and dead code elimination. The resulting graph is then serialized to a binary format. At runtime, the graph can be embedded in the binary and interpreted to generate the witness.

## Usage
See this [example project](https://github.com/philsippl/semaphore-witness-example) for Semaphore with more details on building. 

See this `semaphore-rs` for an example at runtime.
https://github.com/worldcoin/semaphore-rs/blob/62f556bdc1a2a25021dcccc97af4dfa522ab5789/src/protocol/mod.rs#L161-L163

## Benchmarks

### [semaphore-rs](https://github.com/worldcoin/semaphore-rs/tree/main)
**TLDR: For semaphore circuit (depth 30) `circom-witness-rs` is ~25x faster than wasm and ~10x faster than native c++ version.**
```
cargo bench --bench=criterion --features=bench,depth_30
```

With `circom-witness-rs`:q
```
witness_30              time:   [993.84 µs 996.62 µs 999.42 µs]
```

With wasm witness generator from [`circom-compat`](https://github.com/arkworks-rs/circom-compat/blob/master/src/witness/witness_calculator.rs):
```
witness_30              time:   [24.630 ms 24.693 ms 24.759 ms]
```

With native c++ witness generator from circom: `9.640ms`

## Unimplemented features

It's still missing quite a few operations that need to be implemented. The list of supported and unsupported operations can be found:
https://github.com/philsippl/circom-witness-rs/blob/e889cedde49a8929812b825aede55d9668118302/src/generate.rs#L61-L89
