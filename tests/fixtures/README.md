# End-to-end circuit fixtures

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
cargo test --release --features test-world-id --test world_id_witness
cargo test --release --features test-world-id-query --test world_id_query_witness
```
