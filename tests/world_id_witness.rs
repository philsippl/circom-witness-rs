mod common;

use std::{env, fs, path::PathBuf};

use circom_witness_rs::{calculate_witness, generate::generate_witness_graph, init_graph};
use ruint::aliases::U256;

use common::{assert_witnesses_equal, circom_inputs, wasm_witness, world_id_black_box_functions};

const INPUT_JSON: &str = include_str!("fixtures/world_id_oprf_nullifier_input.json");
const EXPECTED_NULLIFIER: &str =
    "21342856517406476000190785734870568200315738457615815351702849709270076362125";

#[test]
fn world_id_oprf_nullifier_wasm_and_rust_witnesses_are_identical() {
    if option_env!("CIRCOM_WITNESS_TEST_CIRCUIT") != Some("OPRFNullifierProof") {
        eprintln!("skipping World ID parity test because a different test circuit was built");
        return;
    }

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let circom_root = root.join("tests/fixtures/world-id-protocol/circom");
    let circuit = circom_root.join("main/OPRFNullifierProof.circom");
    assert!(
        circuit.is_file(),
        "World ID fixture is missing; run `git submodule update --init`"
    );
    if let Some(configured_circuit) =
        env::var_os("CIRCOM_WITNESS").or_else(|| env::var_os("WITNESS_CPP"))
    {
        assert_eq!(
            fs::canonicalize(configured_circuit).unwrap(),
            fs::canonicalize(&circuit).unwrap(),
            "the test feature must be built against its World ID fixture"
        );
    }

    let wasm_witness = wasm_witness(&circuit, "OPRFNullifierProof", INPUT_JSON, &[&circom_root]);
    let expected_nullifier: U256 = serde_json::from_str(&format!("\"{EXPECTED_NULLIFIER}\""))
        .expect("expected nullifier is valid");
    assert_eq!(wasm_witness[1], expected_nullifier);

    let graph_bytes = generate_witness_graph().unwrap();
    let graph = init_graph(&graph_bytes).unwrap();
    let functions = world_id_black_box_functions();
    let rust_witness =
        calculate_witness(circom_inputs(INPUT_JSON), &graph, Some(&functions)).unwrap();

    assert_witnesses_equal(&rust_witness, &wasm_witness);
}
