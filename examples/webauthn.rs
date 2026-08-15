//! WebAuthn autoresearch example: native bigint kernels selected by generated function name.
//!
//! This deliberately lives outside the witness interpreter. It demonstrates how a downstream
//! crate can register circuit-library functions without adding those specializations to
//! `circom-witness-rs` itself. Generic bit and integer decomposition optimizations remain in the
//! graph runtime and contain no WebAuthn-specific names or layouts.
//!
//! The pinned circuit source, reproducible artifact commands, fuzzing notes, and benchmark results
//! live in `examples/webauthn/README.md`.
//!
//! ```text
//! cargo run --release --example webauthn -- --graph graph.bin --reference reference.wtns --reference-only
//! ```

use std::{
    collections::HashMap,
    env, fs,
    hint::black_box,
    ops::Range,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use ark_bn254::Fr;
use circom_witness_rs::profile::{profile_graph, ProfileConfig};
use circom_witness_rs::{
    custom::{
        record_fuzz_corpus_with, verify_fuzz_corpus_with, FuzzConfig, FuzzCorpus,
        NativeRuntimeCoverage, NativeRuntimeFunction, NativeRuntimeOutcome, RuntimeCallInfo,
        RuntimeFunctionMatcher,
    },
    get_inputs_buffer, get_inputs_size, init_graph, populate_inputs, try_get_input_mapping, Graph,
    M,
};
use eyre::{bail, ensure, Context as _};
use num_bigint::{BigInt, BigUint, Sign};
use ruint::aliases::U256;
use serde_json::Value;
use sha2::{Digest as _, Sha256};

const MAX_LIMBS: usize = 50;
const DEFAULT_FUZZ_SEED: u64 = 0x7765_6261_7574_686e;
const SOURCE_REVISION: &str = "0fb5b4aa1398281c2fd3dbe14db147e05b61f201";
const DEFAULT_INPUT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/examples/webauthn/webauthn-circom/scripts/input_webauthn_default.json"
);

#[derive(Debug)]
struct Config {
    graph: PathBuf,
    input: PathBuf,
    reference: Option<PathBuf>,
    iterations: usize,
    reference_only: bool,
    coverage: bool,
    fuzz_cases: usize,
    fuzz_seed: u64,
    record_fuzz_corpus: Option<PathBuf>,
    fuzz_corpus: Option<PathBuf>,
    profile_llm: Option<PathBuf>,
}

fn usage() -> &'static str {
    "usage: webauthn --graph GRAPH [--input INPUT.json] [--reference REFERENCE.wtns] \
     [--iterations N] [--reference-only] \
     [--record-fuzz-corpus PATH --fuzz-cases N --fuzz-seed N | --fuzz-corpus PATH] \
     [--profile-llm REPORT.txt] [--no-coverage]"
}

fn parse_config() -> eyre::Result<Option<Config>> {
    let mut arguments = env::args().skip(1);
    let mut graph = None;
    let mut input = PathBuf::from(DEFAULT_INPUT);
    let mut reference = None;
    let mut iterations = 10_usize;
    let mut reference_only = false;
    let mut coverage = true;
    let mut fuzz_cases = 0_usize;
    let mut fuzz_seed = DEFAULT_FUZZ_SEED;
    let mut record_fuzz_corpus = None;
    let mut fuzz_corpus = None;
    let mut profile_llm = None;
    while let Some(argument) = arguments.next() {
        let mut value = || {
            arguments
                .next()
                .ok_or_else(|| eyre::eyre!("{argument} requires a value\n{}", usage()))
        };
        match argument.as_str() {
            "--graph" => graph = Some(PathBuf::from(value()?)),
            "--input" => input = PathBuf::from(value()?),
            "--reference" => reference = Some(PathBuf::from(value()?)),
            "--iterations" => iterations = value()?.parse()?,
            "--reference-only" | "--optimized-only" => reference_only = true,
            "--fuzz-cases" => fuzz_cases = value()?.parse()?,
            "--fuzz-seed" => fuzz_seed = value()?.parse()?,
            "--record-fuzz-corpus" => record_fuzz_corpus = Some(PathBuf::from(value()?)),
            "--fuzz-corpus" => fuzz_corpus = Some(PathBuf::from(value()?)),
            "--profile-llm" => profile_llm = Some(PathBuf::from(value()?)),
            "--no-coverage" => coverage = false,
            "--help" | "-h" => {
                println!("{}", usage());
                return Ok(None);
            }
            _ => bail!("unknown argument {argument:?}\n{}", usage()),
        }
    }
    ensure!(iterations > 0, "iterations must be greater than zero");
    ensure!(
        record_fuzz_corpus.is_none() || fuzz_corpus.is_none(),
        "--record-fuzz-corpus and --fuzz-corpus are mutually exclusive"
    );
    ensure!(
        record_fuzz_corpus.is_some() || fuzz_cases == 0,
        "--fuzz-cases requires --record-fuzz-corpus"
    );
    ensure!(
        record_fuzz_corpus.is_none() || fuzz_cases > 0,
        "--record-fuzz-corpus requires --fuzz-cases greater than zero"
    );
    ensure!(
        !reference_only || reference.is_some(),
        "--reference-only requires --reference"
    );
    Ok(Some(Config {
        graph: graph.ok_or_else(|| eyre::eyre!(usage()))?,
        input,
        reference,
        iterations,
        reference_only,
        coverage,
        fuzz_cases,
        fuzz_seed,
        record_fuzz_corpus,
        fuzz_corpus,
        profile_llm,
    }))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn witness_sha256(witness: &[U256]) -> String {
    let mut digest = Sha256::new();
    for value in witness {
        digest.update(value.to_le_bytes::<32>());
    }
    format!("{:x}", digest.finalize())
}

fn flatten_json(value: &Value, output: &mut Vec<U256>) -> eyre::Result<()> {
    match value {
        Value::Array(values) => {
            for value in values {
                flatten_json(value, output)?;
            }
        }
        Value::String(value) => output.push(U256::from_str_radix(value, 10)?),
        Value::Number(value) => output.push(U256::from_str_radix(&value.to_string(), 10)?),
        _ => bail!("Circom input values must be decimal strings, numbers, or arrays"),
    }
    Ok(())
}

fn read_inputs(path: &Path) -> eyre::Result<HashMap<String, Vec<U256>>> {
    let object: serde_json::Map<String, Value> =
        serde_json::from_slice(&fs::read(path).wrap_err("failed to read input JSON")?)
            .wrap_err("failed to parse input JSON")?;
    object
        .into_iter()
        .map(|(name, value)| {
            let mut values = Vec::new();
            flatten_json(&value, &mut values)?;
            Ok((name, values))
        })
        .collect()
}

fn scalar(call: RuntimeCallInfo<'_>, index: usize) -> Option<Fr> {
    let [value] = call.argument(index)? else {
        return None;
    };
    Some(*value)
}

fn dimension(value: Fr) -> Option<usize> {
    usize::try_from(BigUint::from(value)).ok()
}

fn dimensions(call: RuntimeCallInfo<'_>) -> Option<(usize, usize)> {
    let n = dimension(scalar(call, 0)?)?;
    let k = dimension(scalar(call, 1)?)?;
    (n > 0 && n <= 256 && k > 0 && k <= MAX_LIMBS).then_some((n, k))
}

fn limbs<'a>(call: RuntimeCallInfo<'a>, index: usize, count: usize) -> Option<&'a [Fr]> {
    call.argument(index)?.get(..count)
}

fn compose_limbs(values: &[Fr], n: usize) -> Option<BigUint> {
    let bound = BigUint::from(1_u8) << n;
    values
        .iter()
        .enumerate()
        .try_fold(BigUint::from(0_u8), |value, (index, limb)| {
            let limb = BigUint::from(*limb);
            (limb < bound).then(|| value + (limb << (n * index)))
        })
}

fn u64_limb(value: Fr, n: usize) -> Option<u64> {
    if n > 64 {
        return None;
    }
    let value: U256 = value.into();
    let value = u64::try_from(value).ok()?;
    (n == 64 || value < (1_u64 << n)).then_some(value)
}

fn write_limbs(value: &BigUint, n: usize, output: &mut [Fr]) {
    let mask = (BigUint::from(1_u8) << n) - BigUint::from(1_u8);
    for (index, destination) in output.iter_mut().enumerate() {
        *destination = Fr::from((value >> (n * index)) & &mask);
    }
}

fn balanced_integer(value: Fr) -> BigInt {
    let value: U256 = value.into();
    if value > M >> 1 {
        BigInt::from_biguint(Sign::Minus, BigUint::from(M - value))
    } else {
        BigInt::from_biguint(Sign::Plus, BigUint::from(value))
    }
}

fn compose_balanced_limbs(values: &[Fr], n: usize) -> BigInt {
    values
        .iter()
        .enumerate()
        .fold(BigInt::from(0_u8), |value, (index, limb)| {
            value + (balanced_integer(*limb) << (n * index))
        })
}

fn write_signed_limbs(value: &BigUint, negative: bool, n: usize, output: &mut [Fr]) {
    write_limbs(value, n, output);
    if negative {
        output.iter_mut().for_each(|limb| *limb = -*limb);
    }
}

fn mod_inv(call: RuntimeCallInfo<'_>, output: &mut [Fr]) -> eyre::Result<NativeRuntimeOutcome> {
    let Some((n, k)) = dimensions(call) else {
        return Ok(NativeRuntimeOutcome::Fallback);
    };
    let (Some(value), Some(modulus)) = (limbs(call, 2, k), limbs(call, 3, k)) else {
        return Ok(NativeRuntimeOutcome::Fallback);
    };
    let (Some(value), Some(modulus)) = (compose_limbs(value, n), compose_limbs(modulus, n)) else {
        return Ok(NativeRuntimeOutcome::Fallback);
    };
    if output.len() < k || modulus <= BigUint::from(2_u8) {
        return Ok(NativeRuntimeOutcome::Fallback);
    }
    let inverse = if value == BigUint::from(0_u8) {
        value
    } else {
        value.modpow(&(&modulus - BigUint::from(2_u8)), &modulus)
    };
    write_limbs(&inverse, n, &mut output[..k]);
    Ok(NativeRuntimeOutcome::Handled)
}

fn long_div2(call: RuntimeCallInfo<'_>, output: &mut [Fr]) -> eyre::Result<NativeRuntimeOutcome> {
    let (Some(n), Some(k), Some(m)) = (
        scalar(call, 0).and_then(dimension),
        scalar(call, 1).and_then(dimension),
        scalar(call, 2).and_then(dimension),
    ) else {
        return Ok(NativeRuntimeOutcome::Fallback);
    };
    if n == 0
        || n > 256
        || k == 0
        || k > MAX_LIMBS
        || m >= MAX_LIMBS
        || k + m >= MAX_LIMBS
        || output.len() != 2 * MAX_LIMBS
    {
        return Ok(NativeRuntimeOutcome::Fallback);
    }
    let (Some(dividend), Some(divisor)) = (limbs(call, 3, k + m), limbs(call, 4, k)) else {
        return Ok(NativeRuntimeOutcome::Fallback);
    };
    if divisor[k - 1] == Fr::from(0_u64) {
        return Ok(NativeRuntimeOutcome::Fallback);
    }
    let (Some(dividend), Some(divisor)) = (compose_limbs(dividend, n), compose_limbs(divisor, n))
    else {
        return Ok(NativeRuntimeOutcome::Fallback);
    };
    if divisor == BigUint::from(0_u8) {
        bail!("Circom long_div2 divisor is zero");
    }
    let quotient = &dividend / &divisor;
    let remainder = dividend % divisor;
    if (&quotient >> (n * (m + 1))) != BigUint::from(0_u8)
        || (&remainder >> (n * k)) != BigUint::from(0_u8)
    {
        bail!("Circom long_div2 result exceeds its limb bounds");
    }
    write_limbs(&quotient, n, &mut output[..m + 1]);
    write_limbs(&remainder, n, &mut output[MAX_LIMBS..MAX_LIMBS + k]);
    Ok(NativeRuntimeOutcome::Handled)
}

fn short_div_norm(
    call: RuntimeCallInfo<'_>,
    output: &mut [Fr],
) -> eyre::Result<NativeRuntimeOutcome> {
    let Some((n, k)) = dimensions(call) else {
        return Ok(NativeRuntimeOutcome::Fallback);
    };
    let (Some(dividend), Some(divisor)) = (limbs(call, 2, k + 1), limbs(call, 3, k)) else {
        return Ok(NativeRuntimeOutcome::Fallback);
    };
    if output.len() != 1 {
        return Ok(NativeRuntimeOutcome::Fallback);
    }
    if n <= 64 {
        let mut dividend_limbs = [0_u64; MAX_LIMBS + 1];
        for (source, destination) in dividend.iter().zip(&mut dividend_limbs) {
            let Some(value) = u64_limb(*source, n) else {
                return Ok(NativeRuntimeOutcome::Fallback);
            };
            *destination = value;
        }
        let mut divisor_limbs = [0_u64; MAX_LIMBS];
        for (source, destination) in divisor.iter().zip(&mut divisor_limbs) {
            let Some(value) = u64_limb(*source, n) else {
                return Ok(NativeRuntimeOutcome::Fallback);
            };
            *destination = value;
        }
        if divisor_limbs[k - 1] == 0 {
            return Ok(NativeRuntimeOutcome::Fallback);
        }

        let base = 1_u128 << n;
        let mask = base - 1;
        let numerator = u128::from(dividend_limbs[k]) * base + u128::from(dividend_limbs[k - 1]);
        let mut quotient = (numerator / u128::from(divisor_limbs[k - 1])).min(mask) as u64;
        let mut product = [0_u64; MAX_LIMBS + 1];
        let mut carry = 0_u128;
        for index in 0..k {
            let value = u128::from(divisor_limbs[index]) * u128::from(quotient) + carry;
            product[index] = (value & mask) as u64;
            carry = value >> n;
        }
        product[k] = carry as u64;
        let greater_than_dividend = |value: &[u64]| {
            value[..k + 1]
                .iter()
                .zip(&dividend_limbs[..k + 1])
                .rev()
                .find_map(|(left, right)| (left != right).then_some(left > right))
                .unwrap_or(false)
        };
        if greater_than_dividend(&product) {
            let Some(next) = quotient.checked_sub(1) else {
                return Ok(NativeRuntimeOutcome::Fallback);
            };
            quotient = next;
            let mut borrow = 0_u128;
            for index in 0..=k {
                let left = u128::from(product[index]);
                let right = if index < k {
                    u128::from(divisor_limbs[index])
                } else {
                    0
                } + borrow;
                let (difference, next_borrow) = if left >= right {
                    (left - right, 0)
                } else {
                    (base + left - right, 1)
                };
                product[index] = difference as u64;
                borrow = next_borrow;
            }
            if greater_than_dividend(&product) {
                let Some(next) = quotient.checked_sub(1) else {
                    return Ok(NativeRuntimeOutcome::Fallback);
                };
                quotient = next;
            }
        }
        output[0] = Fr::from(quotient);
        return Ok(NativeRuntimeOutcome::Handled);
    }

    let (Some(dividend), Some(divisor)) = (compose_limbs(dividend, n), compose_limbs(divisor, n))
    else {
        return Ok(NativeRuntimeOutcome::Fallback);
    };
    if divisor == BigUint::from(0_u8) {
        return Ok(NativeRuntimeOutcome::Fallback);
    }
    let quotient = dividend / divisor;
    if quotient >= (BigUint::from(1_u8) << n) {
        return Ok(NativeRuntimeOutcome::Fallback);
    }
    output[0] = Fr::from(quotient);
    Ok(NativeRuntimeOutcome::Handled)
}

fn long_scalar_mult(
    call: RuntimeCallInfo<'_>,
    output: &mut [Fr],
) -> eyre::Result<NativeRuntimeOutcome> {
    let Some((n, k)) = dimensions(call) else {
        return Ok(NativeRuntimeOutcome::Fallback);
    };
    let (Some(scalar), Some(operand)) = (scalar(call, 2), limbs(call, 3, k)) else {
        return Ok(NativeRuntimeOutcome::Fallback);
    };
    if output.len() < k + 1 {
        return Ok(NativeRuntimeOutcome::Fallback);
    }
    if n <= 64 {
        let Some(scalar) = u64_limb(scalar, n) else {
            return Ok(NativeRuntimeOutcome::Fallback);
        };
        let scalar = u128::from(scalar);
        let mask = (1_u128 << n) - 1;
        let mut carry = 0_u128;
        for (source, destination) in operand.iter().zip(&mut output[..k]) {
            let Some(source) = u64_limb(*source, n) else {
                return Ok(NativeRuntimeOutcome::Fallback);
            };
            let product = u128::from(source) * scalar + carry;
            *destination = Fr::from((product & mask) as u64);
            carry = product >> n;
        }
        output[k] = Fr::from(carry as u64);
        return Ok(NativeRuntimeOutcome::Handled);
    }
    let scalar = BigUint::from(scalar);
    if scalar >= (BigUint::from(1_u8) << n) {
        return Ok(NativeRuntimeOutcome::Fallback);
    }
    let Some(operand) = compose_limbs(operand, n) else {
        return Ok(NativeRuntimeOutcome::Fallback);
    };
    write_limbs(&(scalar * operand), n, &mut output[..k + 1]);
    Ok(NativeRuntimeOutcome::Handled)
}

fn long_gt(call: RuntimeCallInfo<'_>, output: &mut [Fr]) -> eyre::Result<NativeRuntimeOutcome> {
    let Some((n, k)) = dimensions(call) else {
        return Ok(NativeRuntimeOutcome::Fallback);
    };
    let (Some(left), Some(right)) = (limbs(call, 2, k), limbs(call, 3, k)) else {
        return Ok(NativeRuntimeOutcome::Fallback);
    };
    if output.len() != 1 {
        return Ok(NativeRuntimeOutcome::Fallback);
    }
    if n <= 64 {
        for (left, right) in left.iter().zip(right).rev() {
            let (Some(left), Some(right)) = (u64_limb(*left, n), u64_limb(*right, n)) else {
                return Ok(NativeRuntimeOutcome::Fallback);
            };
            if left != right {
                output[0] = Fr::from(left > right);
                return Ok(NativeRuntimeOutcome::Handled);
            }
        }
        return Ok(NativeRuntimeOutcome::Handled);
    }
    let (Some(left), Some(right)) = (compose_limbs(left, n), compose_limbs(right, n)) else {
        return Ok(NativeRuntimeOutcome::Fallback);
    };
    output[0] = Fr::from(left > right);
    Ok(NativeRuntimeOutcome::Handled)
}

fn long_sub(call: RuntimeCallInfo<'_>, output: &mut [Fr]) -> eyre::Result<NativeRuntimeOutcome> {
    let Some((n, k)) = dimensions(call) else {
        return Ok(NativeRuntimeOutcome::Fallback);
    };
    let (Some(left), Some(right)) = (limbs(call, 2, k), limbs(call, 3, k)) else {
        return Ok(NativeRuntimeOutcome::Fallback);
    };
    if output.len() < k {
        return Ok(NativeRuntimeOutcome::Fallback);
    }
    if n <= 64 {
        let base = 1_u128 << n;
        let mut borrow = 0_u128;
        for ((left, right), destination) in left.iter().zip(right).zip(&mut output[..k]) {
            let (Some(left), Some(right)) = (u64_limb(*left, n), u64_limb(*right, n)) else {
                return Ok(NativeRuntimeOutcome::Fallback);
            };
            let left = u128::from(left);
            let right = u128::from(right) + borrow;
            let (difference, next_borrow) = if left >= right {
                (left - right, 0)
            } else {
                (base + left - right, 1)
            };
            *destination = Fr::from(difference as u64);
            borrow = next_borrow;
        }
        return Ok(NativeRuntimeOutcome::Handled);
    }
    let (Some(left), Some(right)) = (compose_limbs(left, n), compose_limbs(right, n)) else {
        return Ok(NativeRuntimeOutcome::Fallback);
    };
    let modulus = BigUint::from(1_u8) << (n * k);
    let difference = if left >= right {
        left - right
    } else {
        modulus + left - right
    };
    write_limbs(&difference, n, &mut output[..k]);
    Ok(NativeRuntimeOutcome::Handled)
}

fn long_add(call: RuntimeCallInfo<'_>, output: &mut [Fr]) -> eyre::Result<NativeRuntimeOutcome> {
    let Some((n, k)) = dimensions(call) else {
        return Ok(NativeRuntimeOutcome::Fallback);
    };
    let (Some(left), Some(right)) = (limbs(call, 2, k), limbs(call, 3, k)) else {
        return Ok(NativeRuntimeOutcome::Fallback);
    };
    if output.len() <= k {
        return Ok(NativeRuntimeOutcome::Fallback);
    }
    if n <= 64 {
        let mask = (1_u128 << n) - 1;
        let mut carry = 0_u128;
        for ((left, right), destination) in left.iter().zip(right).zip(&mut output[..k]) {
            let (Some(left), Some(right)) = (u64_limb(*left, n), u64_limb(*right, n)) else {
                return Ok(NativeRuntimeOutcome::Fallback);
            };
            let sum = u128::from(left) + u128::from(right) + carry;
            *destination = Fr::from((sum & mask) as u64);
            carry = sum >> n;
        }
        output[k] = Fr::from(carry as u64);
        return Ok(NativeRuntimeOutcome::Handled);
    }
    let (Some(left), Some(right)) = (compose_limbs(left, n), compose_limbs(right, n)) else {
        return Ok(NativeRuntimeOutcome::Fallback);
    };
    write_limbs(&(left + right), n, &mut output[..k + 1]);
    Ok(NativeRuntimeOutcome::Handled)
}

fn long_sub_mod(
    call: RuntimeCallInfo<'_>,
    output: &mut [Fr],
) -> eyre::Result<NativeRuntimeOutcome> {
    let Some((n, k)) = dimensions(call) else {
        return Ok(NativeRuntimeOutcome::Fallback);
    };
    let (Some(left), Some(right), Some(modulus)) =
        (limbs(call, 2, k), limbs(call, 3, k), limbs(call, 4, k))
    else {
        return Ok(NativeRuntimeOutcome::Fallback);
    };
    if output.len() <= k {
        return Ok(NativeRuntimeOutcome::Fallback);
    }
    let (Some(left), Some(right), Some(modulus)) = (
        compose_limbs(left, n),
        compose_limbs(right, n),
        compose_limbs(modulus, n),
    ) else {
        return Ok(NativeRuntimeOutcome::Fallback);
    };
    let limb_modulus = BigUint::from(1_u8) << (n * k);
    let difference = if right > left {
        let modulus_minus_right = (modulus + &limb_modulus - right) % &limb_modulus;
        left + modulus_minus_right
    } else {
        left - right
    };
    write_limbs(&difference, n, &mut output[..k + 1]);
    Ok(NativeRuntimeOutcome::Handled)
}

fn signed_long_to_short(
    call: RuntimeCallInfo<'_>,
    output: &mut [Fr],
) -> eyre::Result<NativeRuntimeOutcome> {
    let Some((n, k)) = dimensions(call) else {
        return Ok(NativeRuntimeOutcome::Fallback);
    };
    let Some(value) = limbs(call, 2, k) else {
        return Ok(NativeRuntimeOutcome::Fallback);
    };
    if output.len() != MAX_LIMBS + 1 {
        return Ok(NativeRuntimeOutcome::Fallback);
    }
    let value = compose_balanced_limbs(value, n);
    let negative = value.sign() == Sign::Minus;
    let magnitude = value.magnitude();
    if magnitude >> (n * MAX_LIMBS) != BigUint::from(0_u8) {
        return Ok(NativeRuntimeOutcome::Fallback);
    }
    write_signed_limbs(magnitude, negative, n, &mut output[..MAX_LIMBS]);
    output[MAX_LIMBS] = Fr::from(negative);
    Ok(NativeRuntimeOutcome::Handled)
}

fn signed_fp_carry(
    call: RuntimeCallInfo<'_>,
    output: &mut [Fr],
) -> eyre::Result<NativeRuntimeOutcome> {
    let Some((n, k)) = dimensions(call) else {
        return Ok(NativeRuntimeOutcome::Fallback);
    };
    let Some(m) = scalar(call, 2).and_then(dimension) else {
        return Ok(NativeRuntimeOutcome::Fallback);
    };
    let (Some(value), Some(modulus)) = (limbs(call, 3, k), limbs(call, 4, k)) else {
        return Ok(NativeRuntimeOutcome::Fallback);
    };
    if m == 0 || m >= MAX_LIMBS || output.len() != 2 * MAX_LIMBS {
        return Ok(NativeRuntimeOutcome::Fallback);
    }
    let value = compose_balanced_limbs(value, n);
    let Some(modulus) = compose_limbs(modulus, n) else {
        return Ok(NativeRuntimeOutcome::Fallback);
    };
    if modulus == BigUint::from(0_u8) {
        return Ok(NativeRuntimeOutcome::Fallback);
    }
    let negative = value.sign() == Sign::Minus;
    let magnitude = value.magnitude();
    let mut quotient = magnitude / &modulus;
    let mut remainder = magnitude % &modulus;
    if negative && remainder != BigUint::from(0_u8) {
        quotient += BigUint::from(1_u8);
        remainder = &modulus - remainder;
    }
    if (&quotient >> (n * m)) != BigUint::from(0_u8)
        || (&remainder >> (n * k)) != BigUint::from(0_u8)
    {
        return Ok(NativeRuntimeOutcome::Fallback);
    }
    write_signed_limbs(&quotient, negative, n, &mut output[..m]);
    write_limbs(&remainder, n, &mut output[MAX_LIMBS..MAX_LIMBS + k]);
    Ok(NativeRuntimeOutcome::Handled)
}

fn split(call: RuntimeCallInfo<'_>, output: &mut [Fr]) -> eyre::Result<NativeRuntimeOutcome> {
    let (Some(value), Some(n), Some(m)) = (
        scalar(call, 0),
        scalar(call, 1).and_then(dimension),
        scalar(call, 2).and_then(dimension),
    ) else {
        return Ok(NativeRuntimeOutcome::Fallback);
    };
    if output.len() != 2 || n > 256 || m > 256 || n + m > 256 {
        return Ok(NativeRuntimeOutcome::Fallback);
    }
    let value = BigUint::from(value);
    let low_mask = (BigUint::from(1_u8) << n) - BigUint::from(1_u8);
    let high_mask = (BigUint::from(1_u8) << m) - BigUint::from(1_u8);
    output[0] = Fr::from(&value & low_mask);
    output[1] = Fr::from((value >> n) & high_mask);
    Ok(NativeRuntimeOutcome::Handled)
}

type RuntimeHandler =
    for<'a> fn(RuntimeCallInfo<'a>, &mut [Fr]) -> eyre::Result<NativeRuntimeOutcome>;

fn runtime_function(name: &str, handler: RuntimeHandler) -> NativeRuntimeFunction {
    NativeRuntimeFunction::try_named(
        format!("webauthn::{name}"),
        RuntimeFunctionMatcher::numeric_suffix(name),
        handler,
    )
}

fn webauthn_runtime_functions(
    tracked: bool,
) -> (Vec<NativeRuntimeFunction>, Vec<NativeRuntimeCoverage>) {
    let mut functions = Vec::new();
    let mut coverage = Vec::new();
    for (name, handler) in [
        ("mod_inv", mod_inv as RuntimeHandler),
        ("long_div2", long_div2),
        ("short_div_norm", short_div_norm),
        ("long_scalar_mult", long_scalar_mult),
        ("long_gt", long_gt),
        ("long_sub", long_sub),
        ("long_add", long_add),
        ("long_sub_mod", long_sub_mod),
        ("signed_long_to_short", signed_long_to_short),
        ("get_signed_Fp_carry_witness", signed_fp_carry),
        ("SplitFn", split),
    ] {
        let function = runtime_function(name, handler);
        if tracked {
            let (function, handler_coverage) = function.tracked();
            functions.push(function);
            coverage.push(handler_coverage);
        } else {
            functions.push(function);
        }
    }
    (functions, coverage)
}

fn benchmark(graph: &Graph, inputs: &[U256], iterations: usize) -> eyre::Result<Vec<Duration>> {
    let mut evaluator = graph.evaluator(None)?;
    black_box(evaluator.evaluate(black_box(inputs))?.len());
    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let started = Instant::now();
        black_box(evaluator.evaluate(black_box(inputs))?.len());
        samples.push(started.elapsed());
    }
    samples.sort_unstable();
    Ok(samples)
}

fn median_ms(samples: &[Duration]) -> f64 {
    samples[samples.len() / 2].as_secs_f64() * 1_000.0
}

fn format_samples(samples: &[Duration]) -> String {
    samples
        .iter()
        .map(|sample| format!("{:.3}", sample.as_secs_f64() * 1_000.0))
        .collect::<Vec<_>>()
        .join(",")
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

fn read_wtns(path: &Path) -> eyre::Result<(Vec<U256>, String)> {
    let bytes = fs::read(path).wrap_err("failed to read reference WTNS")?;
    let file_hash = sha256(&bytes);
    ensure!(bytes.starts_with(b"wtns"), "invalid WTNS magic");
    let mut cursor = 4;
    ensure!(take_u32(&bytes, &mut cursor)? == 2, "expected WTNS v2");
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
                ensure!(field_size == 32, "expected BN254 WTNS field size");
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
    ensure!(witness.len() == count * 32, "invalid WTNS witness length");
    Ok((
        witness
            .chunks_exact(32)
            .map(|value| U256::from_le_bytes::<32>(value.try_into().unwrap()))
            .collect(),
        file_hash,
    ))
}

fn assert_equal(expected: &[U256], actual: &[U256], label: &str) -> eyre::Result<()> {
    ensure!(expected.len() == actual.len(), "{label} lengths differ");
    if let Some(index) = expected.iter().zip(actual).position(|(a, b)| a != b) {
        bail!(
            "{label} differs at witness element {index}: expected {}, got {}",
            expected[index],
            actual[index]
        );
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum FuzzDomain {
    Limb43,
    Byte,
    Challenge248,
}

fn input_range(
    name: &str,
    inputs: &HashMap<String, Vec<U256>>,
    mapping: &HashMap<String, usize>,
    buffer_len: usize,
) -> eyre::Result<Range<usize>> {
    let start = *mapping
        .get(name)
        .ok_or_else(|| eyre::eyre!("missing input mapping for {name:?}"))?;
    let length = inputs
        .get(name)
        .ok_or_else(|| eyre::eyre!("missing input value for {name:?}"))?
        .len();
    let end = start
        .checked_add(length)
        .ok_or_else(|| eyre::eyre!("input range for {name:?} overflowed"))?;
    ensure!(
        end <= buffer_len,
        "input range for {name:?} is out of bounds"
    );
    Ok(start..end)
}

fn fuzz_domains(
    inputs: &HashMap<String, Vec<U256>>,
    mapping: &HashMap<String, usize>,
    buffer_len: usize,
) -> eyre::Result<Vec<(Range<usize>, FuzzDomain)>> {
    [
        ("r", FuzzDomain::Limb43),
        ("s", FuzzDomain::Limb43),
        ("pubkey", FuzzDomain::Limb43),
        ("auth_data", FuzzDomain::Byte),
        ("client_data", FuzzDomain::Byte),
        ("challenge", FuzzDomain::Challenge248),
    ]
    .into_iter()
    .map(|(name, domain)| Ok((input_range(name, inputs, mapping, buffer_len)?, domain)))
    .collect()
}

fn constrain_fuzz_case(
    candidate: &mut [U256],
    base: &[U256],
    domains: &[(Range<usize>, FuzzDomain)],
) {
    let entropy = candidate.to_vec();
    candidate.copy_from_slice(base);
    for (range, domain) in domains {
        for index in range.clone() {
            candidate[index] = match domain {
                FuzzDomain::Limb43 => {
                    // Keep bigint inputs inside the circuit's six 43-bit limb representation.
                    let value: U256 = entropy[index] & ((U256::ONE << 43_usize) - U256::ONE);
                    value.max(U256::ONE)
                }
                FuzzDomain::Byte => entropy[index] & U256::from(0xff_u64),
                FuzzDomain::Challenge248 => entropy[index] & ((U256::ONE << 248) - U256::ONE),
            };
        }
    }
}

fn print_coverage(coverage: &[NativeRuntimeCoverage]) -> eyre::Result<()> {
    let snapshots = coverage
        .iter()
        .map(NativeRuntimeCoverage::snapshot)
        .collect::<Vec<_>>();
    let hit = snapshots
        .iter()
        .filter(|snapshot| snapshot.attempts > 0)
        .count();
    let handled = snapshots
        .iter()
        .map(|snapshot| snapshot.handled)
        .sum::<u64>();
    let fallbacks = snapshots
        .iter()
        .map(|snapshot| snapshot.fallbacks)
        .sum::<u64>();
    let errors = snapshots
        .iter()
        .map(|snapshot| snapshot.errors)
        .sum::<u64>();
    println!("coverage_handlers={}", snapshots.len());
    println!("coverage_handlers_hit={hit}");
    println!("coverage_handled_calls={handled}");
    println!("coverage_fallback_calls={fallbacks}");
    println!("coverage_error_calls={errors}");
    for snapshot in &snapshots {
        println!("coverage={}", serde_json::to_string(snapshot)?);
    }
    ensure!(
        errors == 0,
        "native runtime coverage observed handler errors"
    );
    Ok(())
}

fn main() -> eyre::Result<()> {
    let Some(config) = parse_config()? else {
        return Ok(());
    };

    let graph_started = Instant::now();
    let graph_bytes = fs::read(&config.graph).wrap_err("failed to read graph")?;
    let graph_hash = sha256(&graph_bytes);
    let original = init_graph(&graph_bytes)?;
    let graph_load = graph_started.elapsed();
    let input_bytes = fs::read(&config.input).wrap_err("failed to read input JSON")?;
    let input_hash = sha256(&input_bytes);
    let inputs = read_inputs(&config.input)?;
    let input_names = inputs.keys().cloned().collect::<Vec<_>>();
    let input_mapping = try_get_input_mapping(&input_names, &original)?;
    let mut input_buffer = get_inputs_buffer(get_inputs_size(&original));
    populate_inputs(&inputs, &input_mapping, &mut input_buffer);

    let (mut reference_witness, reference_hash) = if let Some(path) = &config.reference {
        let (witness, hash) = read_wtns(path)?;
        (Some(witness), Some(hash))
    } else {
        (None, None)
    };
    let expected = if config.reference_only {
        reference_witness
            .take()
            .expect("configuration requires a reference witness")
    } else {
        let mut portable_evaluator = original.evaluator(None)?;
        let expected = portable_evaluator.evaluate(&input_buffer)?.to_vec();
        drop(portable_evaluator);
        if let Some(reference) = &reference_witness {
            assert_equal(reference, &expected, "portable/reference")?;
        }
        expected
    };

    if config.coverage || config.record_fuzz_corpus.is_some() || config.fuzz_corpus.is_some() {
        let (functions, coverage) = webauthn_runtime_functions(config.coverage);
        let instrumented = original.customizer().runtime_functions(functions).build()?;
        let mut evaluator = instrumented.evaluator(None)?;
        assert_equal(
            &expected,
            evaluator.evaluate(&input_buffer)?,
            "reference/instrumented",
        )?;
        drop(evaluator);

        if let Some(path) = &config.record_fuzz_corpus {
            let started = Instant::now();
            let domains = fuzz_domains(&inputs, &input_mapping, input_buffer.len())?;
            let corpus = record_fuzz_corpus_with(
                &original,
                FuzzConfig {
                    cases: config.fuzz_cases,
                    seed: config.fuzz_seed,
                },
                None,
                |_, candidate| constrain_fuzz_case(candidate, &input_buffer, &domains),
            )?;
            fs::write(path, serde_json::to_vec_pretty(&corpus)?)
                .wrap_err("failed to write fuzz corpus")?;
            println!("fuzz_corpus_recorded={}", corpus.len());
            println!(
                "fuzz_corpus_record_ms={:.3}",
                started.elapsed().as_secs_f64() * 1_000.0
            );
            println!(
                "fuzz_corpus_path={}",
                serde_json::to_string(&path.display().to_string())?
            );
        }
        if let Some(path) = &config.fuzz_corpus {
            let started = Instant::now();
            let corpus: FuzzCorpus =
                serde_json::from_slice(&fs::read(path).wrap_err("failed to read fuzz corpus")?)
                    .wrap_err("failed to decode fuzz corpus")?;
            let domains = fuzz_domains(&inputs, &input_mapping, input_buffer.len())?;
            let report = verify_fuzz_corpus_with(&instrumented, &corpus, None, |_, candidate| {
                constrain_fuzz_case(candidate, &input_buffer, &domains)
            })?;
            println!("fuzz_corpus=matched");
            println!("fuzz_cases={}", report.cases);
            println!(
                "fuzz_corpus_replay_ms={:.3}",
                started.elapsed().as_secs_f64() * 1_000.0
            );
            println!(
                "fuzz_corpus_path={}",
                serde_json::to_string(&path.display().to_string())?
            );
        }
        if config.coverage {
            print_coverage(&coverage)?;
        }
    }

    let (runtime_functions, _) = webauthn_runtime_functions(false);
    let runtime_handler_count = runtime_functions.len();
    let customization_started = Instant::now();
    let optimized = original
        .customizer()
        .runtime_functions(runtime_functions)
        .build()?;
    let customization = customization_started.elapsed();

    // A real application performs the setup above once, keeps `optimized` for the process
    // lifetime, and creates one evaluator per worker/thread. Its per-witness hot path is simply:
    // `let witness: &[U256] = optimized_evaluator.evaluate(&input_buffer)?;`
    // Copy that slice only when it must remain valid after the evaluator's next call.
    let mut optimized_evaluator = optimized.evaluator(None)?;
    assert_equal(
        &expected,
        optimized_evaluator.evaluate(&input_buffer)?,
        "portable/optimized",
    )?;
    drop(optimized_evaluator);

    let portable_samples = if config.reference_only {
        Vec::new()
    } else {
        benchmark(&original, &input_buffer, config.iterations)?
    };
    let optimized_samples = benchmark(&optimized, &input_buffer, config.iterations)?;
    let optimized_median = median_ms(&optimized_samples);
    let profile_summary = if let Some(path) = &config.profile_llm {
        let report = profile_graph(
            &optimized,
            &input_buffer,
            None,
            ProfileConfig {
                warmup_iterations: 1,
                benchmark_iterations: config.iterations.clamp(1, 5),
                trace_iterations: 1,
                instruction_block_size: 4_096,
                max_hotspots: 20,
            },
        )?;
        let mut text = format!(
            "ARTIFACT source_revision={SOURCE_REVISION} graph_sha256={graph_hash} input_sha256={input_hash}\n"
        );
        text.push_str(&report.to_llm_text());
        fs::write(path, text).wrap_err("failed to write LLM profile")?;
        Some((path, report.benchmark.p50_ns))
    } else {
        None
    };

    println!("source_revision={SOURCE_REVISION}");
    println!(
        "graph_path={}",
        serde_json::to_string(&config.graph.display().to_string())?
    );
    println!("graph_sha256={graph_hash}");
    println!(
        "input_path={}",
        serde_json::to_string(&config.input.display().to_string())?
    );
    println!("input_sha256={input_hash}");
    if let Some(path) = &config.reference {
        println!(
            "reference_path={}",
            serde_json::to_string(&path.display().to_string())?
        );
        println!(
            "reference_wtns_sha256={}",
            reference_hash.as_deref().unwrap()
        );
    }
    println!("witness_elements={}", expected.len());
    println!("witness_payload_sha256={}", witness_sha256(&expected));
    println!("equivalence=matched");
    println!(
        "comparison_mode={}",
        if config.reference_only {
            "reference-only"
        } else {
            "portable-and-reference"
        }
    );
    println!("graph_load_ms={:.3}", graph_load.as_secs_f64() * 1_000.0);
    println!(
        "customization_build_ms={:.3}",
        customization.as_secs_f64() * 1_000.0
    );
    println!("runtime_handlers={runtime_handler_count}");
    println!(
        "runtime_instructions_before={}",
        original.runtime_instruction_count()
    );
    println!(
        "runtime_instructions_after={}",
        optimized.runtime_instruction_count()
    );
    if !portable_samples.is_empty() {
        let portable_median = median_ms(&portable_samples);
        println!("portable_samples_ms={}", format_samples(&portable_samples));
        println!("portable_median_ms={portable_median:.3}");
        println!("speedup={:.2}x", portable_median / optimized_median);
    }
    println!(
        "optimized_samples_ms={}",
        format_samples(&optimized_samples)
    );
    println!("optimized_median_ms={optimized_median:.3}");
    if let Some((path, p50_ns)) = profile_summary {
        println!(
            "profile_llm_path={}",
            serde_json::to_string(&path.display().to_string())?
        );
        println!("profile_benchmark_p50_ns={p50_ns}");
    }
    Ok(())
}
