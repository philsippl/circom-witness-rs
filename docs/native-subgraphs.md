# Autoresearch and native witness extension guide

The serialized witness graph remains the portable, canonical implementation. Native extensions are
process-local overlays created after loading a graph and cannot be serialized. The runtime has two
generic interception points regardless of how many circuit-specific optimizations applications
develop: closed static DAG regions and portable runtime-function calls.

## Boundary contract

A `NativeSubgraph` contains:

- a diagnostic name;
- input node IDs, in callback argument order;
- output node IDs, in callback result order; and
- an infallible or fallible Rust callback over BN254 `Fr` values.

The library walks backwards from every output and stops at the declared inputs. Everything reached
is covered by the replacement. Customization fails when:

- a graph input is reached without appearing in the input boundary;
- an input is unused or is not available before the first output;
- a covered value is consumed outside the region without appearing in the output boundary;
- a witness output would be hidden; or
- two replacements overlap.

Multiple outputs let one native call expose intermediate values required by the remaining
interpreter, without recomputing the native region. After validation, covered graph instructions are
removed and one native instruction produces all declared outputs. The usual division scheduler,
black-box binding, stateful evaluator, and witness APIs continue to work on the customized `Graph`.

## Dynamic runtime-function contract

Some Circom witness code cannot become a static graph because a branch, loop, or array index depends
on an input. The graph builder embeds that code as portable runtime IR. A
`NativeRuntimeFunction` can optionally handle calls at this layer, including calls nested inside an
otherwise interpreted function.

Each callback receives `RuntimeCallInfo` with:

- the exact function ID and generated name;
- the flat field argument buffer;
- the original top-level argument sizes and `argument(index)` slices;
- the Circom variable-arena size; and
- the requested result count plus a zeroed output slice of that length.

A matcher can select an exact generated name or a base name followed by a strictly numeric
specialization suffix. A callback returns `Handled` after filling every output, or `Fallback` when
the particular signature is unsupported. On fallback the output scratch is cleared before the next
handler; if all handlers decline, execution continues in the portable IR. This makes incremental
optimizations safe: one implementation can cover common limb widths while unusual shapes retain the
canonical behavior.

Use `NativeRuntimeFunction::named` or `try_named` to give generated handlers stable profiler labels.
Calling `tracked()` returns the handler plus a shared `NativeRuntimeCoverage` handle. Its snapshots
report attempts, handled calls, fallbacks, errors, and every generated function/argument/result
shape encountered. Tracking is deliberately opt-in because it synchronizes on each attempted call;
build a separately tracked graph for verification, then benchmark an untracked graph.

Argument boundaries are preserved at top-level graph calls and recursively for nested runtime-IR
calls. This is the key requirement for the WebAuthn-style helpers (`long_div2`, scalar
multiplication, comparisons, carry witnesses, and split functions), whose meaning depends on
specialized array lengths. Multi-output callbacks cover helpers returning limb arrays. Repeated bit
extractions can either be one multi-output static subgraph or a runtime-function handler, depending
on how the builder lowered that circuit. Generic field-operation fast paths remain core runtime
optimizations rather than extension callbacks. The prepared interpreter also collapses contiguous
outputs of one runtime invocation into a single compact instruction and lets native handlers write
those outputs directly into the value arena; extension authors do not need to batch them manually.

## Autoresearch workflow

1. Load the unmodified graph and inspect `Graph::nodes()` and
   `Graph::runtime_function_names()`.
2. Run `circom-witness-profile` or `profile_graph` on representative inputs. Feed its JSON or
   line-oriented `STRUCTURE`/`SELF`/`INCLUSIVE` rankings to the research agent. `STRUCTURE` samples
   contain root, covered, and boundary IDs in the loaded `Graph::nodes()` view; their timing is an
   estimate apportioned from measured instruction blocks.
3. Have a research tool structurally match a costly DAG region or identify an expensive runtime
   function.
4. Generate native Rust plus `NativeSubgraph` and/or `NativeRuntimeFunction` declarations.
5. Register the complete set with `Graph::customizer()` and call `build()` once.
6. Outside the autoresearch loop, run `record_fuzz_corpus` once on the original graph. It stores
   only deterministic random seeds and BLAKE3 hashes of their complete witnesses. Use
   `record_fuzz_corpus_with` for booleans, ranges, encodings, or other circuit-specific domains.
7. In every autoresearch iteration, call `verify_fuzz_corpus` (or its `_with` variant) on only the
   optimized graph. It regenerates the same inputs from their seeds and compares witness hashes;
   the slow original interpreter is not executed.
8. Profile and benchmark again only after corpus replay passes, and keep the original graph as the
   fallback and reference implementation used to regenerate the corpus when the circuit changes.

Node IDs belong to the semantic node view of a particular loaded graph and are not a stable file
format API. Generated extensions should either pin/hash their graph artifact or rediscover boundaries
structurally. The [Semaphore example](../examples/semaphore.rs) demonstrates the latter approach for
static DAG regions. The [WebAuthn guide](../examples/webauthn/README.md) demonstrates the
complementary runtime-function approach for input-dependent bigint helpers, including a pinned
source, exact argument slicing, selective fallback, call-shape coverage, constrained differential
seed/hash corpus replay, artifact provenance, and an agent-readable benchmark/profile mode.
