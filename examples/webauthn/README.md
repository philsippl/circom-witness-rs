# WebAuthn native-runtime extension example

This example reproduces the performance of the earlier circuit-specific WebAuthn interpreter
optimizations using the public extension API. WebAuthn-specific function names, limb layouts, and
bigint implementations live in [`../webauthn.rs`](../webauthn.rs); the library retains only generic
field, bit-extraction, and power-of-two integer optimizations.

The circuit source is a submodule pinned to
[`privacy-ethereum/webauth-circom`](https://github.com/privacy-ethereum/webauth-circom) commit
`0fb5b4aa1398281c2fd3dbe14db147e05b61f201`. It contains both the exact
`scripts/webauthn_default.circom` entrypoint and its input JSON.

## Set up and generate artifacts

Initialize the pinned source:

```shell
git submodule update --init --recursive -- examples/webauthn/webauthn-circom
corepack yarn --cwd examples/webauthn/webauthn-circom install --frozen-lockfile
```

Generate the graph using this workspace's pinned Circom 2.2.2 compiler integration:

```shell
examples/webauthn/generate-artifacts.sh graph
```

This writes `target/webauthn/webauthn.graph`. Generated artifacts are intentionally not committed.

For an independent WASM reference, put the Circom 2.2.2 binary on `PATH`, then run:

```shell
examples/webauthn/generate-artifacts.sh reference
```

That compiles the pinned source with `--O1` and writes `target/webauthn/reference.wtns` through
Circom's generated WASM witness calculator. `generate-artifacts.sh all` performs both steps.

## Embed the tuned generator in an application

The benchmark executable is not part of the production call path. In a downstream project, move
the handler constructors from `examples/webauthn.rs` into that project's optimization module, then
install the overlay once at startup and retain a stateful evaluator per worker or thread:

```rust
use circom_witness_rs::{
    get_inputs_buffer, get_inputs_size, init_graph, populate_inputs, try_get_input_mapping,
};
use my_project::webauthn_optimization::runtime_functions;

let portable = init_graph(include_bytes!("../artifacts/webauthn.graph"))?;
let optimized = portable
    .customizer()
    .runtime_functions(runtime_functions())
    .build()?;
let mut evaluator = optimized.evaluator(None)?;

let input_names = inputs.keys().cloned().collect::<Vec<_>>();
let input_mapping = try_get_input_mapping(&input_names, &optimized)?;
let mut input_buffer = get_inputs_buffer(get_inputs_size(&optimized));
populate_inputs(&inputs, &input_mapping, &mut input_buffer);

// This is the complete custom witness-generator call on the request/proving hot path.
let witness = evaluator.evaluate(&input_buffer)?;
prover.consume_witness(witness)?;
```

`evaluate` reuses its allocations and returns a borrowed witness slice. Copy it with `to_vec()` if
the witness must outlive the next call on that evaluator. The `portable` graph remains the canonical
implementation used for differential tests; only the customized graph is needed on the production
hot path.

## Reference regression and benchmark

Run the extension against the independently generated WTNS:

```shell
cargo run --release --example webauthn -- \
  --graph target/webauthn/webauthn.graph \
  --reference target/webauthn/reference.wtns \
  --reference-only \
  --iterations 25
```

The source input is selected from the submodule by default. The output is line-oriented
`key=value` data and includes source revision, graph/input/reference hashes, witness payload hash,
handler coverage, sorted samples, and the median. Coverage uses a separately instrumented graph and
is dropped before the timed run; pass `--no-coverage` to skip it.

Expected artifact identities for the pinned source and current graph format are:

| Artifact | SHA-256 |
|---|---|
| Input JSON | `b635e9511a747bb0bea0278d423e3e859b24d386368186c72a8e46e4e0644657` |
| Graph | `c41b4739b62645940f67878d6c4a83872b87bdf3be6caebf6245bc2ca72f9e0e` |
| Reference WTNS | `294c8091d87c2dbec8bc8997d0e892b65e81d5f95a14320081dcaefea1a5e0d8` |
| Witness field payload | `9ba7a4f38e9c11656c07e8b72cfe4b974dab27f224a4fdb60a2da83492a5c177` |

The WTNS contains 3,413,073 BN254 field elements. The example compares every element, not only the
hash.

The v4 graph is a fully prepared execution plan: generic fusion, bit caching, integer lowering, and
division scheduling happen once in `circom-witness-graph-builder`, not in every application
process. The default level 19 zstd encoding is 18,012,360 bytes and its median file-read plus
initialization time was 145.7 ms. Passing `--compression-level -5` to the graph builder produces a
49,585,278-byte latency-oriented artifact that loaded in an 82.9 ms median. The previous load-time
preparation path took roughly 1.25 seconds inside `init_graph`. `graph_load_ms` deliberately excludes
the optional SHA-256 provenance calculation printed by the example.

## Pregenerated differential fuzz corpus

The cached-reference mode is fast, but it is only a single regression fixture. Generate a random
seed/BLAKE3 corpus once with the original portable graph, outside the autoresearch loop:

```shell
cargo run --release --example webauthn -- \
  --graph target/webauthn/webauthn.graph \
  --reference target/webauthn/reference.wtns \
  --reference-only \
  --iterations 1 \
  --record-fuzz-corpus target/webauthn/fuzz-corpus.json \
  --fuzz-cases 2 \
  --fuzz-seed 8603657889543977070
```

This slow command evaluates the original graph once per seed. The resulting JSON array stores only
each seed and the BLAKE3 hash of its complete 3,413,073-field witness. The two-case corpus generated
for this example is checked in as [`fuzz-corpus.json`](fuzz-corpus.json) and is only 264 bytes.

Every autoresearch iteration then evaluates only the optimized graph:

```shell
cargo run --release --example webauthn -- \
  --graph target/webauthn/webauthn.graph \
  --reference target/webauthn/reference.wtns \
  --reference-only \
  --iterations 1 \
  --fuzz-corpus examples/webauthn/fuzz-corpus.json
```

Replay deterministically regenerates each input from its stored seed, hashes the optimized witness
with BLAKE3, and compares it with the pregenerated hash. It never evaluates the original graph.
The seed-to-input mapping is a versioned BLAKE3 stream with rejection sampling, so it does not
depend on an implementation-specific random-number generator and samples field elements uniformly.

The generator keeps bigint values in six 43-bit limbs, byte arrays in `0..=255`, the challenge
inside 248 bits, and array lengths at the pinned fixture's valid values. It deliberately does not
produce proof-valid WebAuthn signatures: its purpose is witness-implementation equivalence over a
broad, safe arithmetic domain. Constraint satisfaction remains a separate circuit test.

Corpus recording is slow because it evaluates the unoptimized portable runtime, but that cost is
paid only once. On the development machine, recording both checked-in seeds took 455.712 seconds.
Replaying both seeds took 307.647 ms total, including two optimized witness evaluations and BLAKE3
hashes of both complete witnesses; the adjacent one-iteration benchmark measured 102.033 ms. Both
stored hashes matched.

## Handler coverage and profiling

The pinned fixture currently reaches five of the eleven registered candidate handlers. Those five
handle 37,462 calls with zero fallbacks or errors. The other helpers exist in the embedded runtime
and are retained for alternative paths and related WebAuthn circuit shapes, but higher-level native
handlers bypass them for this fixture. The emitted per-handler JSON includes every observed function
ID, generated name, argument-size vector, arena size, result size, and outcome count.

To produce the flamegraph-like, LLM-oriented profile after applying the WebAuthn overlay:

```shell
cargo run --release --example webauthn -- \
  --graph target/webauthn/webauthn.graph \
  --reference target/webauthn/reference.wtns \
  --reference-only \
  --iterations 5 \
  --profile-llm target/webauthn/profile.txt
```

The report starts with the source, graph, and input identities, followed by `PROFILE`, `BENCHMARK`,
`STRUCTURE`, `SELF`, and `INCLUSIVE` records.

## Before and after

Measurements used release builds, a warmed stateful evaluator, the same pinned input, and excluded
graph loading from witness latency:

| Stage | Median | Relative to initial portable path |
|---|---:|---:|
| Portable hybrid interpreter before WebAuthn specialization | 2,155.110 ms | 1.00x |
| Extension API with native runtime handlers only | 348.115 ms | 6.19x |
| Extension API plus generic bit/integer/field/runtime-call optimizations | 98.481 ms | 21.88x |
| Original hard-coded optimization branch, re-run alongside final extension | 105.268 ms | 20.47x |

The final extension is 6.4% faster than the hard-coded branch while removing every WebAuthn-specific
optimization from the library interpreter. The extension row used 25 timed evaluations; its
samples ranged from 98.136 ms to 108.219 ms and the witness matched all 3,413,073 reference fields.
A generic runtime lowering accounts for the last improvement: contiguous outputs from one runtime
invocation are materialized directly by one compact instruction instead of dispatching and caching
one instruction per output.
