# 🏎️ circom-witness-rs

**Update Sept. 2025:** After a long radio silence, I've added more supported ops, some bug fixes, and *most importantly support for unconstrained control flow* (e.g. allowing the ternary operator `bool ? a : b`), which has been wished for many times and been quite a limitation to this project. See the section about blackbox functions in the usage section for more details.

## Description

This crate provides a fast witness generator for Circom circuits, serving as a drop-in replacement for Circom's witness generator. It was created in response to the slow performance of Circom's WASM generator for larger circuits, which also necessitates a WASM runtime, often a cumbersome requirement. The native C++ generator, though faster, depends on x86 assembly for field operations, rendering it impractical for use on other platforms (e.g., cross-compiling to ARM for mobile devices).

`circom-witness-rs` comes with two modes:

1. Generate the static execution graph required for the witness generation at build time.
2. Generate the witness elements at runtime from serialized graph.

In the first mode, it generates the c++ version of the witness generator through circom and links itself against it. The c++ code is made accessible to rust through [`cxx`](https://github.com/dtolnay/cxx). It hooks all field functions (which are x86 assembly in the original generator), such that it can recreate the execution graph through symblic execution. The execution graph is further optimized through constant propagation and dead code elimination. The resulting graph is then serialized to a binary format. At runtime, the graph can be embedded in the binary and interpreted to generate the witness.

## Usage

**1. (One-off) Create and optimize graph:**
```rust
    witness::generate::build_witness().unwrap();
```

**2. (At runtime) Generate witness:**
```rust
const BYTES: &[u8] = include_bytes!("../graph.bin");
fn main() {
    let inputs: HashMap<String, Vec<U256>> = serde_json::from_str("{...}").unwrap();
    let graph = witness::init_graph(BYTES).unwrap();
    let witness = witness::calculate_witness(inputs, &graph, None).unwrap();
}
```

**📦 Blackbox functions**

Unconstrained control flow is also supported through configurable blackbox functions. This also includes the commonly requested ternary operator. Importantly, any unconstained / dynamic control flow needs to live in circom functions (i.e. cannot live in templates), so requires small modifications to existing circuits. Those functions are currently limited to a single return value. 

*Important:* Those functions only get hooked iff you prefix them with `bbf*`.

```rust
    let mut bbfs: HashMap<String, BlackBoxFunction> = HashMap::new();
    // Instead of a closure, this can also be a function
    bbfs.insert("bbf_inv".to_string(), Arc::new(move |args: &[Fr]| -> Fr {
        // Circom code:
        // function bbf_inv(in) {
        //     return in!=0 ? 1/in : 0;
        // }
        args[0].inverse().unwrap_or(Fr::ZERO)
    }));

    let witness = witness::calculate_witness(inputs.clone(), &graph, Some(&bbfs)).unwrap();
```

See this [example project](https://github.com/philsippl/semaphore-witness-example) for Semaphore with an example. 

See `semaphore-rs` for an [example at runtime](https://github.com/worldcoin/semaphore-rs/blob/62f556bdc1a2a25021dcccc97af4dfa522ab5789/src/protocol/mod.rs#L161-L163).

All of those example were used with `circom compiler 2.2.2` ([6f782d7](https://github.com/iden3/circom/tree/6f782d7)). Using a different version of circom might cause issues due to different c++ code being generated.

## Benchmarks

### [semaphore-rs](https://github.com/worldcoin/semaphore-rs/tree/main)
**TLDR: For semaphore circuit (depth 30) `circom-witness-rs` is ~25x faster than wasm and ~10x faster than native c++ version.**
```
cargo bench --bench=criterion --features=bench,depth_30
```

With `circom-witness-rs`:
```
witness_30              time:   [993.84 µs 996.62 µs 999.42 µs]
```

With wasm witness generator from [`circom-compat`](https://github.com/arkworks-rs/circom-compat/blob/master/src/witness/witness_calculator.rs):
```
witness_30              time:   [24.630 ms 24.693 ms 24.759 ms]
```

With native c++ witness generator from circom: `9.640ms`

As a nice side effect of the graph optimizations, the binary size is also reduced heavily. In the example of Semaphore the binary size is reduced from `1.3MB` (`semaphore.wasm`) to `350KB` (`graph.bin`). 
