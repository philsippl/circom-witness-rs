// SPDX-License-Identifier: GPL-3.0-only

mod common;

use std::path::Path;

use circom_witness_graph_builder::generate_witness_graph_from_file;
use circom_witness_rs::{calculate_witness, init_graph};

use common::{assert_witnesses_equal, circom_inputs, wasm_witnesses};

struct Fixture {
    circuit: &'static str,
    name: &'static str,
    inputs: &'static [&'static str],
}

// These use circomlib's own entrypoint circuits and representative inputs from its upstream tests.
// Keep the list focused: the purpose is broad witness-IR parity, not retesting circomlib itself.
const FIXTURES: &[Fixture] = &[
    Fixture {
        circuit: "lessthan.circom",
        name: "lessthan",
        inputs: &[
            r#"{"in":[333,444]}"#,
            r#"{"in":[1,1]}"#,
            r#"{"in":[661,660]}"#,
            r#"{"in":[0,1]}"#,
        ],
    },
    Fixture {
        circuit: "mux4_1.circom",
        name: "mux4_1",
        inputs: &[
            r#"{"selector":0}"#,
            r#"{"selector":7}"#,
            r#"{"selector":15}"#,
        ],
    },
    Fixture {
        circuit: "babyadd_tester.circom",
        name: "babyadd_tester",
        inputs: &[
            r#"{"x1":0,"y1":1,"x2":0,"y2":1}"#,
            r#"{
                "x1":"17777552123799933955779906779655732241715742912184938656739573121738514868268",
                "y1":"2626589144620713026669568689430873010625803728049924121243784502389097019475",
                "x2":"16540640123574156134436876038791482806971768689494387082833631921987005038935",
                "y2":"20819045374670962167435360035096875258406992893633759881276124905556507972311"
            }"#,
        ],
    },
    Fixture {
        circuit: "mimc_sponge_hash_test.circom",
        name: "mimc_sponge_hash_test",
        inputs: &[r#"{"ins":[1,2],"k":0}"#],
    },
    Fixture {
        circuit: "sha256_2_test.circom",
        name: "sha256_2_test",
        inputs: &[r#"{"a":"1","b":"2"}"#],
    },
];

#[test]
fn upstream_circomlib_wasm_and_rust_witnesses_are_identical() {
    let circomlib = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/circomlib");
    let circuits = circomlib.join("test/circuits");
    assert!(
        circuits.is_dir(),
        "circomlib fixture is missing; run `git submodule update --init`"
    );

    for fixture in FIXTURES {
        let circuit = circuits.join(fixture.circuit);
        let wasm_witnesses = wasm_witnesses(&circuit, fixture.name, fixture.inputs, &[]);

        let graph_bytes = generate_witness_graph_from_file(&circuit, &[]).unwrap();
        let graph = init_graph(&graph_bytes).unwrap();

        for (&input, wasm_witness) in fixture.inputs.iter().zip(&wasm_witnesses) {
            let rust_witness = calculate_witness(circom_inputs(input), &graph, None).unwrap();
            assert_witnesses_equal(&rust_witness, wasm_witness);
        }
    }
}
