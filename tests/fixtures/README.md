# End-to-end circuit fixtures

Circomlib is pinned as a submodule under
`graph-builder/tests/fixtures/circomlib`. Its upstream test entrypoints and
representative upstream inputs are used by the CI-only `test-circomlib`
feature to compare complete Circom WASM and Rust witnesses. The circuits are
not copied into or packaged with the MIT runtime crate.

`world-id-protocol` is a shallow Git submodule pinned to the upstream
[`worldcoin/world-id-protocol`](https://github.com/worldcoin/world-id-protocol)
repository at commit `cfabe989375b9652933ab12251c36b9a8f8618fc`. Initialize it
after cloning this repository with:

```console
git submodule update --init
```

The World ID parity tests use the upstream production `OPRFQueryProof` and
`OPRFNullifierProof` entrypoints with their known-answer inputs. They exercise
all five runtime black-box functions used by World ID's Rust proof code.

Run the test with Circom 2.2.2 and Node.js available:

```console
cargo test -p circom-witness-graph-builder --release --features test-circomlib --test circomlib_witness
cargo test --release --features test-world-id --test world_id_witness
cargo test --release --features test-world-id-query --test world_id_query_witness
```
