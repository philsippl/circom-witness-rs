# ProveKit V1 Circom witness benchmark reference

This directory preserves the sources, inputs, harness, and results used to validate the hybrid
`circom-witness-rs` graph/runtime implementation against the ProveKit V1 Circom workloads. It is a
reference branch, not intended to be merged into the runtime crate.

The `upstream` gitlink pins the benchmark campaign itself. The three gitlinks below `sources/` pin
the circuit repositories selected by that campaign. Initialize everything with:

```sh
git submodule update --init --recursive
bash benchmarks/provekit-v1/setup.sh
```

## Pinned inputs

| Source | Revision |
|---|---|
| ProveKit benchmark campaign | `a697cf4cf21148263dc3f166a39ab5927d36d45f` |
| Self circuits | `15b167e3543a9dff1dbb16fcf71a45fe4625cf9e` |
| World ID protocol | `85aeeef539961cae5a63de794997b507a5975717` |
| WebAuthn Circom | `0fb5b4aa1398281c2fd3dbe14db147e05b61f201` |
| Circom compiler | `6f782d7313793b3dc18cc3b38d2335eead9f5d50` (`2.2.2`) |

The six entrypoints and their fixture locations are recorded in [`circuits.tsv`](circuits.tsv).
Self, Passport P1, World ID, and WebAuthn are compiled with `--O1` to preserve the benchmark's
witness-to-signal ordering.

## Results

Measured on Darwin arm64 with Rust 1.95.0, Node 26.5.0, and Circom 2.2.2. One warm-up preceded each
sample set. Only witness generation was run; proving was not run.

| Circuit | Witness elements | Graph size | Hybrid hot median | Existing ProveKit backend | Speedup | Warm WASM median | Speedup |
|---|---:|---:|---:|---:|---:|---:|---:|
| Self RSA-4096 register | 967,666 | 4,548,709 B | 403.400 ms | 2,851.167 ms (`rust-witness`) | 7.07x | 3,406.359 ms | 8.44x |
| Self VC disclose | 145,722 | 405,473 B | 3.313 ms | 73.320 ms (`rust-witness`) | 22.13x | 116.092 ms | 35.04x |
| Passport P1 | 965,282 | 4,549,230 B | 430.186 ms | 2,989.547 ms (`rust-witness`) | 6.95x | 3,415.550 ms | 7.94x |
| WebAuthn | 3,413,073 | 27,175,055 B | 862.136 ms | 47,061.531 ms (`rust-witness`) | 54.59x | 53,456.554 ms | 62.00x |
| World ID OPRF query | 34,155 | 173,558 B | 0.958 ms | 514.669 ms (`wasmi`) | 537.23x | 36.905 ms | 38.52x |
| World ID OPRF nullifier | 73,756 | 231,061 B | 2.337 ms | 1,734.262 ms (`wasmi`) | 742.09x | 105.855 ms | 45.30x |

`rust-witness` is pinned to 0.1.6 and `wasmi` to 0.46.0, matching ProveKit. The Wasmi numbers use
ProveKit's exact per-call function, which constructs the interpreter and serializes WTNS each time;
they are not a hot-runtime comparison. The warm-WASM column times repeated `calculateWitness`
calls after module construction and is the cleaner hot calculation comparison.

The hybrid measurement calls `WitnessEvaluator::evaluate` with an already loaded graph and a
pre-populated positional input buffer. Graph loading, JSON parsing, input mapping, and the first
evaluation are excluded. These are therefore hot-path results, not cold-start results. A fair cold
comparison must time `init_graph` through the first completed witness as a single region.

Sample counts were 5-20 for the hybrid and Rust/Wasmi paths, except the very slow WebAuthn
`rust-witness` and warm-WASM baselines, which used one measured sample after warm-up.

### WebAuthn native bigint specialization

Profiling showed that interpreted `circom-pairing` bigint helpers consumed most of the remaining
WebAuthn runtime. The witness runtime now recognizes Circom's numeric function specializations and
executes `long_div2`, `short_div_norm`, `long_scalar_mult`, and `SplitFn` with native `BigUint`
division, multiplication, and bit-range operations. Unsupported signatures still fall back to the
portable IR interpreter; the constraint graph and witness signal ordering are unchanged.

On the same machine and graph, the 15-sample hot median fell from 2,155.110 ms to 862.136 ms: a
60.0% time reduction, or 2.50x speedup over the previous hybrid path. Graph loading remained a
separate cold-start cost (1,182.560 ms in the final run).

## Correctness

Every hybrid witness element was compared with the corresponding Circom WASM witness. The locked
campaign hashes matched for the five frozen workloads:

| Workload | WTNS SHA-256 |
|---|---|
| World ID OPRF query | `89844b3d8e0b0a9a58075659b694f2e0f5582a198430da6d8101a48707f7446f` |
| World ID OPRF nullifier | `b5c2bf1c167f8fe77cf13bf96db143c21aa19f27f6b7cc9317b255c43d32f568` |
| Self VC disclose | `53a4ce55036d040275e3cb5548ad771f67789e018098eab92656beb0e218807f` |
| Self RSA-4096 register | `9a785c0e2a974ca751777bb6824ebd8e6d4be1b43224cc1a0cbe6cc02d663c6a` |
| WebAuthn | `294c8091d87c2dbec8bc8997d0e892b65e81d5f95a14320081dcaefea1a5e0d8` |

Passport P1 was generated from the pinned source and fixture and matched all 965,282 WASM witness
elements; its generated WTNS hash was
`0754ae5733f6e3a4bf4baaf87b732cb57d5e633e671517f14ab05d19602cf3cd`.

The optimized WebAuthn witness matched all 3,413,073 cached WASM fields. Hashing the concatenated
32-byte little-endian field payload (without the WTNS header) produced
`9ba7a4f38e9c11656c07e8b72cfe4b974dab27f224a4fdb60a2da83492a5c177`. This payload hash is used for
fast iteration without rerunning the WASM generator; the full reference WTNS hash remains the value
in the table above.

## Harness

The reusable command-line harness is [`../../examples/witness-benchmark.rs`](../../examples/witness-benchmark.rs):

```sh
cargo run --release --example witness-benchmark -- \
  graph.bin input.json reference.wtns 10
```

It loads and prepares the graph once, verifies every output field against WTNS v2, performs one
untimed evaluation, then reports the deterministic field-payload SHA-256, sorted witness-only
samples, and their median. Use `-` in place of `REFERENCE.wtns` and `0` iterations for a single
hash-only correctness run against an already recorded payload hash.
