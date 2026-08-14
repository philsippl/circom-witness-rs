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

### Two modes: off the shelf or autoresearch-tuned

This crate can be used in two complementary modes:

- **Off the shelf:** load a generated graph and evaluate it with the portable interpreter. This is
  the default: no circuit-specific Rust, research step, or maintenance burden is required.
- **Autoresearch-tuned:** keep the same graph as the canonical implementation, but let an LLM agent
  profile one important circuit and generate project-local native implementations for its hottest
  repeated subgraphs or dynamic functions. The rest of the witness still runs in the interpreter.

The second mode is deliberately an extension workflow rather than a growing collection of
circuit-specific optimizations in this repository. A downstream project owns the generated Rust
module or companion crate, while `circom-witness-rs` supplies the stable hooks, profiler, portable
fallback, and differential fuzz tester. See the
**[autoresearch and native extension guide](docs/native-subgraphs.md)** for the full contracts and
workflow.

A typical downstream project would:

1. Generate and retain the ordinary graph artifact.
2. Run `circom-witness-profile` on representative inputs and give the JSON or LLM-oriented report
   to its research agent.
3. Have the agent add structural matchers and `NativeSubgraph` or `NativeRuntimeFunction`
   implementations to that project's own source tree.
4. Differentially fuzz the tuned graph against the original, then compare their uninstrumented
   benchmarks in CI.
5. Ship the original graph together with the verified overlay. Runtime handlers can decline
   unsupported call shapes and use the portable implementation; the application can likewise keep
   the original graph available if a static overlay no longer matches.
6. Pin or hash the graph artifact and repeat the research workflow when the circuit changes.

This makes tuning optional and incremental: start with the off-the-shelf evaluator, then specialize
only projects where witness-generation latency justifies maintaining circuit-specific native code.
Conceptually, the native overlay is a fine-tuning layer for one circuit: it specializes the generic
witness engine without forking it or giving up the interpreter as the reference implementation.

Production integration remains a normal library call. The downstream optimization module accepts
the portable graph and returns a customized `Graph`; omitting that one step selects the off-the-shelf
mode:

```rust
let portable = circom_witness_rs::init_graph(include_bytes!("../circuit.graph"))?;
let graph = my_circuit_optimizations::apply(&portable)?; // Omit for off-the-shelf mode.
let mut evaluator = graph.evaluator(None)?;
let witness = evaluator.evaluate(&input_buffer)?;
```

### Native witness extensions

Applications can replace expensive regions of a loaded graph with native Rust while leaving the
rest in the interpreter. A replacement names its input and output boundary using node IDs from
`Graph::nodes()`. The library traces the region between those boundaries and rejects overlaps,
missing inputs, or internal values that are still used by the surrounding graph.

```rust
use circom_witness_rs::custom::{fuzz_equivalence, FuzzConfig, NativeSubgraph};

// These IDs are normally emitted or structurally discovered by an application-specific research
// tool. This example replaces two graph outputs with one native call.
let replacement = NativeSubgraph::new(
    "native-heavy-region",
    vec![input_a_node, input_b_node],
    vec![output_node, intermediate_output_node],
    |inputs, outputs| {
        outputs[0] = native_implementation(inputs[0], inputs[1]);
        outputs[1] = another_native_output(inputs[0], inputs[1]);
    },
);
let optimized = graph.customizer().native_subgraph(replacement).build()?;

// Random BN254 field inputs, with a deterministic seed for reproduction.
fuzz_equivalence(&graph, &optimized, FuzzConfig::default(), None)?;
```

Use `fuzz_equivalence_with` when inputs such as booleans or bounded integers need circuit-specific
constraints. Native callbacks are process-local and intentionally are not serialized into graph
files. Keep the original graph as the portable source of truth, build replacements after loading,
and key generated matchers to the exact graph version or discover boundaries structurally.

[`examples/semaphore.rs`](examples/semaphore.rs) is a complete example: circuit-specific code finds
Semaphore's repeated Merkle-tree multiplexers, replaces each with native field arithmetic, and
differentially fuzzes the customized graph before use.

The same builder can intercept dynamic Circom functions, including calls nested inside another
runtime function. This is useful for input-dependent bigint code such as WebAuthn:

```rust
use circom_witness_rs::custom::{
    NativeRuntimeFunction, NativeRuntimeOutcome, RuntimeFunctionMatcher,
};

let bigint = NativeRuntimeFunction::new(
    RuntimeFunctionMatcher::numeric_suffix("long_div2"),
    |call, outputs| {
        // Exact array boundaries are retained even though Circom passes a flat field buffer.
        let Some(dividend) = call.argument(0) else {
            return NativeRuntimeOutcome::Fallback;
        };
        if !supported_shape(call.argument_sizes(), call.result_count()) {
            return NativeRuntimeOutcome::Fallback;
        }
        native_long_div2(dividend, call.arguments(), outputs);
        NativeRuntimeOutcome::Handled
    },
);
let optimized = graph.customizer().runtime_function(bigint).build()?;
fuzz_equivalence(&graph, &optimized, FuzzConfig::default(), None)?;
```

`Fallback` tries another matching handler and then the portable runtime IR, so an optimization can
support only the call shapes it understands. `Graph::runtime_function_names()` lists the functions
available for interception. The same API is intended for replacing a whole Poseidon permutation,
bigint helper, or another heavy region with code produced during an autoresearch run. See the
[autoresearch and native extension guide](docs/native-subgraphs.md) for boundary invariants and the
complete workflow.

See this [example project](https://github.com/philsippl/semaphore-witness-example) for Semaphore with an example. 

See `semaphore-rs` for an [example at runtime](https://github.com/worldcoin/semaphore-rs/blob/62f556bdc1a2a25021dcccc97af4dfa522ab5789/src/protocol/mod.rs#L161-L163).

Graph construction is pinned to the [Circom 2.2.2 compiler source](https://github.com/iden3/circom/tree/v2.2.2), so it does not depend on whichever `circom` executable happens to be installed on the host.

### Agent-readable graph profiling

`circom-witness-profile` benchmarks a graph with real Circom input JSON and emits a structured,
flamegraph-like trace:

```shell
cargo run --release --bin circom-witness-profile -- \
  graph.bin input.json --iterations 50 --trace-iterations 2 --top 40 --format llm
```

The default line format uses stable record types (`PROFILE`, `BENCHMARK`, `TRACE`, `MIX`,
`STRUCTURE`, `SELF`, and `INCLUSIVE`) plus explicit key/value fields and JSON-encoded stack paths.
`--format json` emits the complete typed report, while `--format folded` emits conventional
semicolon-separated collapsed stacks. `--output profile.json` writes any format to a file.

Latency statistics come from uninstrumented evaluations. Hotspots come from a separate instrumented
trace and therefore do not distort the reported mean, p50, or p95. Ordinary arithmetic instructions
are timed in low-overhead ranges of 128 compact instructions by default; use `--block-size N` to
change the resolution. Runtime functions, nested calls, black boxes, native subgraphs, and native
runtime handlers receive their own stack frames.

Every instruction hotspot includes half-open `source_node_ranges` into the loaded
`Graph::nodes()` view. `STRUCTURE` records group repeated arithmetic shapes, stop at shared values
and graph outputs, and provide sample root, covered, and boundary node IDs that an agent can use to
generate `NativeSubgraph` matchers. Their times are estimates apportioned from measured instruction
blocks; run with a smaller `--block-size` when ranking nearby candidates, then trust the
uninstrumented before/after benchmark for the final decision.

Customized graphs can be profiled directly through the library API:

```rust
use circom_witness_rs::profile::{profile_graph, ProfileConfig};

let report = profile_graph(&optimized, &input_buffer, None, ProfileConfig::default())?;
println!("{}", report.to_json_pretty()?);
```

The CLI cannot construct application-specific black-box or native callbacks; applications using
those should call `profile_graph` after building their customized `Graph`.

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
