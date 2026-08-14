// SPDX-License-Identifier: GPL-3.0-only

use std::{
    collections::HashMap,
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use ark_bn254::Fr;
use ark_ff::{AdditiveGroup as _, Field as _, LegendreSymbol};
use circom_witness_rs::BlackBoxFunction;
use ruint::aliases::U256;
use serde_json::Value;

const WASM_RUNNER: &str = r#"
const fs = require("fs");

async function main() {
    const witnessCalculatorBuilder = require(process.argv[2]);
    const wasm = fs.readFileSync(process.argv[3]);
    const inputs = JSON.parse(fs.readFileSync(process.argv[4], "utf8"));
    const calculator = await witnessCalculatorBuilder(wasm);
    const witness = await calculator.calculateWitness(inputs, 0);
    process.stdout.write(JSON.stringify(witness.map((value) => value.toString())));
}

main().catch((error) => {
    console.error(error);
    process.exit(1);
});
"#;

struct TempDir(PathBuf);

impl TempDir {
    fn new(circuit_name: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir().join(format!(
            "circom-witness-rs-{circuit_name}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run(command: &mut Command) -> Output {
    let description = format!("{command:?}");
    let output = command
        .output()
        .unwrap_or_else(|error| panic!("failed to run {description}: {error}"));
    assert!(
        output.status.success(),
        "{description} failed with {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    output
}

pub fn circom_inputs(input_json: &str) -> HashMap<String, Vec<U256>> {
    let object = serde_json::from_str::<Value>(input_json)
        .unwrap()
        .as_object()
        .unwrap()
        .clone();

    object
        .into_iter()
        .map(|(name, value)| {
            let mut values = Vec::new();
            flatten_values(value, &mut values);
            (name, values)
        })
        .collect()
}

fn flatten_values(value: Value, output: &mut Vec<U256>) {
    match value {
        Value::Array(values) => {
            for value in values {
                flatten_values(value, output);
            }
        }
        value => output.push(serde_json::from_value(value).unwrap()),
    }
}

#[allow(dead_code)]
pub fn wasm_witness(
    circuit: &Path,
    circuit_name: &str,
    input_json: &str,
    library_paths: &[&Path],
) -> Vec<U256> {
    wasm_witnesses(circuit, circuit_name, &[input_json], library_paths)
        .pop()
        .unwrap()
}

#[allow(dead_code)]
pub fn wasm_witnesses(
    circuit: &Path,
    circuit_name: &str,
    input_jsons: &[&str],
    library_paths: &[&Path],
) -> Vec<Vec<U256>> {
    let temp = TempDir::new(circuit_name);
    let circom = env::var_os("CIRCOM").unwrap_or_else(|| "circom".into());
    let mut compile = Command::new(circom);
    compile
        .arg(circuit)
        .arg("--wasm")
        .arg("--O2")
        .arg("--output")
        .arg(temp.path());
    for library_path in library_paths {
        compile.arg("-l").arg(library_path);
    }
    run(&mut compile);

    let input_path = temp.path().join("input.json");
    let runner_path = temp.path().join("calculate_witness.js");
    fs::write(&runner_path, WASM_RUNNER).unwrap();

    let js_dir = temp.path().join(format!("{circuit_name}_js"));
    let node = env::var_os("NODE").unwrap_or_else(|| "node".into());
    input_jsons
        .iter()
        .map(|input_json| {
            fs::write(&input_path, input_json).unwrap();
            let wasm_output = run(Command::new(&node)
                .arg(&runner_path)
                .arg(js_dir.join("witness_calculator.js"))
                .arg(js_dir.join(format!("{circuit_name}.wasm")))
                .arg(&input_path));

            serde_json::from_slice(&wasm_output.stdout).unwrap()
        })
        .collect()
}

pub fn assert_witnesses_equal(rust_witness: &[U256], wasm_witness: &[U256]) {
    assert_eq!(rust_witness.len(), wasm_witness.len());
    for (index, (rust, wasm)) in rust_witness.iter().zip(wasm_witness).enumerate() {
        assert_eq!(rust, wasm, "witness element {index} differs");
    }
}

// Each integration-test target compiles this shared module independently.
#[allow(dead_code)]
pub fn world_id_black_box_functions() -> HashMap<String, BlackBoxFunction> {
    let mut functions = HashMap::<String, BlackBoxFunction>::new();

    functions.insert(
        "bbf_inv".to_owned(),
        Arc::new(|args: &[Fr]| args[0].inverse().unwrap_or(Fr::ZERO)),
    );
    functions.insert(
        "bbf_num_2_bits_helper".to_owned(),
        Arc::new(|args: &[Fr]| {
            let value: U256 = args[0].into();
            let shift: U256 = args[1].into();
            Fr::from((value >> shift.as_limbs()[0] as usize).bit(0))
        }),
    );
    functions.insert(
        "bbf_legendre".to_owned(),
        Arc::new(|args: &[Fr]| match args[0].legendre() {
            LegendreSymbol::Zero => Fr::ZERO,
            LegendreSymbol::QuadraticResidue => Fr::ONE,
            LegendreSymbol::QuadraticNonResidue => -Fr::ONE,
        }),
    );
    functions.insert(
        "bbf_sqrt_input".to_owned(),
        Arc::new(|args: &[Fr]| {
            if args[0] == -Fr::ONE {
                args[2]
            } else {
                args[1]
            }
        }),
    );
    functions.insert(
        "bbf_sqrt_unchecked".to_owned(),
        Arc::new(|args: &[Fr]| args[0].sqrt().unwrap_or(Fr::ZERO)),
    );

    functions
}
