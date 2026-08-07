# Licensing by package

This repository is a Cargo workspace containing packages with separate licenses.

- The root `circom-witness-rs` runtime package is licensed under the [MIT License](LICENSE). It contains the graph format and witness evaluator and does not depend on Circom.
- The `graph-builder` package is licensed under [GNU GPL version 3 only](graph-builder/COPYING). It links directly to Circom's GPLv3 compiler crates and is intentionally kept outside the runtime package.

Each package's `license` field and source-file SPDX identifiers state the applicable license. Third-party dependencies remain subject to their respective licenses.
