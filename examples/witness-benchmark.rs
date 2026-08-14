use std::{collections::HashMap, env, fs, hint::black_box, sync::Arc, time::Instant};

use ark_bn254::Fr;
use ark_ff::{AdditiveGroup as _, Field as _, LegendreSymbol};
use circom_witness_rs::{
    get_input_mapping, get_inputs_buffer, get_inputs_size, init_graph, populate_inputs,
    BlackBoxFunction,
};
use ruint::aliases::U256;
use serde_json::Value;

fn flatten(value: &Value, output: &mut Vec<U256>) -> eyre::Result<()> {
    match value {
        Value::Array(values) => {
            for value in values {
                flatten(value, output)?;
            }
        }
        Value::String(value) => output.push(U256::from_str_radix(value, 10)?),
        Value::Number(value) => output.push(U256::from_str_radix(&value.to_string(), 10)?),
        _ => eyre::bail!("Circom input values must be decimal strings or numbers"),
    }
    Ok(())
}

fn read_inputs(path: &str) -> eyre::Result<HashMap<String, Vec<U256>>> {
    let object: serde_json::Map<String, Value> = serde_json::from_slice(&fs::read(path)?)?;
    object
        .into_iter()
        .map(|(name, value)| {
            let mut values = Vec::new();
            flatten(&value, &mut values)?;
            Ok((name, values))
        })
        .collect()
}

fn world_id_black_boxes() -> HashMap<String, BlackBoxFunction> {
    HashMap::from([
        (
            "bbf_inv".to_owned(),
            Arc::new(|args: &[Fr]| args[0].inverse().unwrap_or(Fr::ZERO)) as BlackBoxFunction,
        ),
        (
            "bbf_num_2_bits_helper".to_owned(),
            Arc::new(|args: &[Fr]| {
                let value: U256 = args[0].into();
                let shift: U256 = args[1].into();
                Fr::from((value >> shift.as_limbs()[0] as usize).bit(0))
            }) as BlackBoxFunction,
        ),
        (
            "bbf_legendre".to_owned(),
            Arc::new(|args: &[Fr]| match args[0].legendre() {
                LegendreSymbol::Zero => Fr::ZERO,
                LegendreSymbol::QuadraticResidue => Fr::ONE,
                LegendreSymbol::QuadraticNonResidue => -Fr::ONE,
            }) as BlackBoxFunction,
        ),
        (
            "bbf_sqrt_input".to_owned(),
            Arc::new(|args: &[Fr]| {
                if args[0] == -Fr::ONE {
                    args[2]
                } else {
                    args[1]
                }
            }) as BlackBoxFunction,
        ),
        (
            "bbf_sqrt_unchecked".to_owned(),
            Arc::new(|args: &[Fr]| args[0].sqrt().unwrap_or(Fr::ZERO)) as BlackBoxFunction,
        ),
    ])
}

fn take_u32(bytes: &[u8], cursor: &mut usize) -> eyre::Result<u32> {
    let value = bytes
        .get(*cursor..*cursor + 4)
        .ok_or_else(|| eyre::eyre!("truncated WTNS"))?;
    *cursor += 4;
    Ok(u32::from_le_bytes(value.try_into().unwrap()))
}

fn take_u64(bytes: &[u8], cursor: &mut usize) -> eyre::Result<u64> {
    let value = bytes
        .get(*cursor..*cursor + 8)
        .ok_or_else(|| eyre::eyre!("truncated WTNS"))?;
    *cursor += 8;
    Ok(u64::from_le_bytes(value.try_into().unwrap()))
}

fn read_wtns(path: &str) -> eyre::Result<Vec<U256>> {
    let bytes = fs::read(path)?;
    eyre::ensure!(bytes.starts_with(b"wtns"), "invalid WTNS magic");
    let mut cursor = 4;
    eyre::ensure!(take_u32(&bytes, &mut cursor)? == 2, "expected WTNS v2");
    let sections = take_u32(&bytes, &mut cursor)?;
    let mut witness_count = None;
    let mut witness = None;
    for _ in 0..sections {
        let kind = take_u32(&bytes, &mut cursor)?;
        let length = usize::try_from(take_u64(&bytes, &mut cursor)?)?;
        let end = cursor
            .checked_add(length)
            .ok_or_else(|| eyre::eyre!("WTNS section overflowed"))?;
        let section = bytes
            .get(cursor..end)
            .ok_or_else(|| eyre::eyre!("truncated WTNS section"))?;
        match kind {
            1 => {
                let field_size = u32::from_le_bytes(section[0..4].try_into().unwrap()) as usize;
                eyre::ensure!(field_size == 32, "expected BN254 WTNS field size");
                witness_count = Some(u32::from_le_bytes(
                    section[4 + field_size..8 + field_size].try_into().unwrap(),
                ) as usize);
            }
            2 => witness = Some(section),
            _ => {}
        }
        cursor = end;
    }
    let count = witness_count.ok_or_else(|| eyre::eyre!("WTNS header is missing"))?;
    let witness = witness.ok_or_else(|| eyre::eyre!("WTNS witness section is missing"))?;
    eyre::ensure!(witness.len() == count * 32, "invalid WTNS witness length");
    Ok(witness
        .chunks_exact(32)
        .map(|value| U256::from_le_bytes::<32>(value.try_into().unwrap()))
        .collect())
}

fn main() -> eyre::Result<()> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    eyre::ensure!(
        (2..=4).contains(&arguments.len()),
        "usage: witness-benchmark GRAPH INPUT [REFERENCE.wtns] [ITERATIONS]"
    );
    let iterations = arguments
        .get(3)
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(10_usize);

    let graph_started = Instant::now();
    let graph = init_graph(&fs::read(&arguments[0])?)?;
    let graph_load = graph_started.elapsed();
    let inputs = read_inputs(&arguments[1])?;
    let mapping = get_input_mapping(&inputs.keys().cloned().collect(), &graph);
    let mut input_buffer = get_inputs_buffer(get_inputs_size(&graph));
    populate_inputs(&inputs, &mapping, &mut input_buffer);
    let black_boxes = world_id_black_boxes();
    let mut evaluator = graph.evaluator(Some(&black_boxes))?;

    let witness = evaluator.evaluate(&input_buffer)?;
    let witness_elements = witness.len();
    if let Some(reference) = arguments.get(2) {
        let reference = read_wtns(reference)?;
        eyre::ensure!(witness.len() == reference.len(), "witness lengths differ");
        for (index, (actual, expected)) in witness.iter().zip(&reference).enumerate() {
            eyre::ensure!(actual == expected, "witness differs at element {index}");
        }
    }

    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let started = Instant::now();
        black_box(evaluator.evaluate(black_box(&input_buffer))?);
        samples.push(started.elapsed());
    }
    samples.sort_unstable();
    println!("graph_load_ms={:.3}", graph_load.as_secs_f64() * 1_000.0);
    println!("witness_elements={witness_elements}");
    println!(
        "samples_ms={}",
        samples
            .iter()
            .map(|sample| format!("{:.3}", sample.as_secs_f64() * 1_000.0))
            .collect::<Vec<_>>()
            .join(",")
    );
    println!(
        "median_ms={:.3}",
        samples[samples.len() / 2].as_secs_f64() * 1_000.0
    );
    Ok(())
}
