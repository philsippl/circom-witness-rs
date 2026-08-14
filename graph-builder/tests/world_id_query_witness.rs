// SPDX-License-Identifier: GPL-3.0-only

mod common;

use std::path::PathBuf;

use circom_witness_graph_builder::generate_witness_graph_from_file;
use circom_witness_rs::{calculate_witness, init_graph};
use ruint::aliases::U256;

use common::{assert_witnesses_equal, circom_inputs, wasm_witness, world_id_black_box_functions};

const INPUT_JSON: &str = include_str!("../../tests/fixtures/world_id_oprf_query_input.json");
const EXPECTED_Q: [&str; 2] = [
    "9674018812144873985515234638873635008708834681175738612597888298086191498827",
    "18818965079786157878748649151755578492493325229415754584538271947197071123195",
];

#[test]
fn world_id_oprf_query_wasm_and_rust_witnesses_are_identical() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_owned();
    let circom_root = root.join("tests/fixtures/world-id-protocol/circom");
    let circuit = circom_root.join("main/OPRFQueryProof.circom");
    assert!(
        circuit.is_file(),
        "World ID fixture is missing; run `git submodule update --init`"
    );
    let wasm_witness = wasm_witness(&circuit, "OPRFQueryProof", INPUT_JSON, &[&circom_root]);
    for (index, expected) in EXPECTED_Q.into_iter().enumerate() {
        let expected: U256 = serde_json::from_str(&format!("\"{expected}\""))
            .expect("expected query output is valid");
        assert_eq!(wasm_witness[index + 1], expected);
    }

    let graph_bytes =
        generate_witness_graph_from_file(&circuit, std::slice::from_ref(&circom_root)).unwrap();
    let graph = init_graph(&graph_bytes).unwrap();
    let functions = world_id_black_box_functions();
    let rust_witness =
        calculate_witness(circom_inputs(INPUT_JSON), &graph, Some(&functions)).unwrap();

    assert_witnesses_equal(&rust_witness, &wasm_witness);
}
