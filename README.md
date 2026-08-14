# 🏎️ circom-witness-rs

**Update Sept. 2025:** After a long radio silence, I've added more supported ops, some bug fixes, and *most importantly support for unconstrained control flow* (e.g. allowing the ternary operator `bool ? a : b`), which has been wished for many times and been quite a limitation to this project. See the section about blackbox functions in the usage section for more details.

## Description

This crate provides a fast witness generator for Circom circuits, serving as a drop-in replacement for Circom's witness generator. It was created in response to the slow performance of Circom's WASM generator for larger circuits, which also necessitates a WASM runtime, often a cumbersome requirement. The native C++ generator, though faster, depends on x86 assembly for field operations, rendering it impractical for use on other platforms (e.g., cross-compiling to ARM for mobile devices).

The repository contains two crates with a graph file as their boundary:

1. `circom-witness-graph-builder` compiles a circuit into a static execution graph as a one-off operation.
2. `circom-witness-rs` loads that graph and generates witness elements at runtime.

In the first mode, it compiles the circuit in-process with Circom 2.2.2 and symbolically executes the compiler's typed witness IR to build an execution graph. No generated C++, native compiler, or Rust/C++ bridge is involved. The graph is optimized through constant propagation and dead code elimination, then lowered into a compact execution program with fused linear combinations, squaring, and multi-output power-of-five instructions. Constants and coefficients are pooled, references are backward-delta encoded, and the result is compressed with Zstandard. At runtime, independent field divisions are scheduled into batches that use one fast modular inversion per batch. Input-dependent function branches, loops, and array indexes are embedded as portable Circom IR and interpreted only at those graph boundaries; the rest of the witness remains precomputed. The graph can be embedded in the binary and interpreted to generate the witness. Legacy compressed and uncompressed Postcard graphs remain readable.

## Usage

**1. (One-off) Create and optimize a graph:**
```shell
cargo run --release -p circom-witness-graph-builder -- circuit.circom graph.bin
```

Additional arguments are treated as Circom library search paths.
For circuits whose reference artifacts use Circom O1, put `--O1` before the circuit path.

**2. (At runtime) Generate witness:**
```rust
const BYTES: &[u8] = include_bytes!("../graph.bin");
fn main() {
    let inputs: HashMap<String, Vec<U256>> = serde_json::from_str("{...}").unwrap();
    let graph = witness::init_graph(BYTES).unwrap();
    let witness = witness::calculate_witness(inputs, &graph, None).unwrap();
}
```

**📦 Dynamic control flow and black-box functions**

Input-dependent control flow in Circom functions is handled automatically by the runtime IR interpreter, including multi-value returns. Dynamic template branches with only local variable and signal effects are lowered to arithmetic selects. Branches that create or conditionally execute components are still rejected.

Black-box callbacks remain available as an explicit escape hatch or native acceleration hook. A Circom function is routed to a callback only when its name starts with `bbf`; callbacks return one field element.

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

For repeated witnesses from the same graph, create a stateful evaluator after populating a
positional input buffer with `get_input_mapping` and `populate_inputs`:

```rust
let mut evaluator = graph.evaluator(Some(&bbfs)).unwrap();
let witness: &[U256] = evaluator.evaluate(&inputs_buffer).unwrap();
```

The evaluator resolves black-box callbacks once and reuses its execution and output buffers. The
returned witness slice is overwritten by the next call to `evaluate` on that evaluator.

See this [example project](https://github.com/philsippl/semaphore-witness-example) for Semaphore with an example. 

See `semaphore-rs` for an [example at runtime](https://github.com/worldcoin/semaphore-rs/blob/62f556bdc1a2a25021dcccc97af4dfa522ab5789/src/protocol/mod.rs#L161-L163).

Graph construction is pinned to the [Circom 2.2.2 compiler source](https://github.com/iden3/circom/tree/v2.2.2), so it does not depend on whichever `circom` executable happens to be installed on the host.

## Licensing

The runtime crate `circom-witness-rs` is licensed under MIT and has no Circom compiler dependency. The separate `circom-witness-graph-builder` crate links to Circom's GPLv3 compiler crates and is licensed under `GPL-3.0-only`. Generated graph files are consumed by the MIT runtime without linking the builder or Circom into runtime applications.

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
