//! Portable interpreter for the small parts of Circom witness code that cannot be represented by
//! a static arithmetic graph (input-dependent branches, loops, or array indexes).

use ark_bn254::Fr;
use eyre::{bail, eyre};
use num_bigint::{BigInt, BigUint, Sign};
use ruint::aliases::U256;
use serde::{Deserialize, Serialize};

use crate::graph::Operation;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeFunction {
    pub name: String,
    pub variable_count: usize,
    pub body: Vec<RuntimeStatement>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuntimeStatement {
    Store {
        offset: RuntimeExpression,
        size: usize,
        value: RuntimeExpression,
    },
    Call(RuntimeExpression),
    Branch {
        condition: RuntimeExpression,
        if_branch: Vec<RuntimeStatement>,
        else_branch: Vec<RuntimeStatement>,
    },
    Loop {
        condition: RuntimeExpression,
        body: Vec<RuntimeStatement>,
    },
    Return {
        value: RuntimeExpression,
        size: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuntimeExpression {
    Field(U256),
    Address(usize),
    Load {
        offset: Box<RuntimeExpression>,
        size: usize,
    },
    Compute {
        operation: RuntimeOperation,
        operands: Vec<RuntimeExpression>,
    },
    Call {
        function: usize,
        arena_size: usize,
        result_size: usize,
        arguments: Vec<(RuntimeExpression, usize)>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuntimeOperation {
    Field(Operation),
    Equal(usize),
    ToAddress,
    AddAddress,
    MulAddress,
}

enum Value {
    Address(usize),
    Fields(Vec<Fr>),
}

impl Value {
    fn address(self) -> eyre::Result<usize> {
        match self {
            Self::Address(value) => Ok(value),
            Self::Fields(_) => bail!("runtime Circom expression is not an address"),
        }
    }

    fn fields(self) -> eyre::Result<Vec<Fr>> {
        match self {
            Self::Fields(values) => Ok(values),
            Self::Address(_) => bail!("runtime Circom expression is not a field value"),
        }
    }
}

enum Flow {
    Continue,
    Return(Vec<Fr>),
}

struct Interpreter<'a> {
    functions: &'a [RuntimeFunction],
    steps_left: usize,
}

impl<'a> Interpreter<'a> {
    fn step(&mut self) -> eyre::Result<()> {
        self.steps_left = self
            .steps_left
            .checked_sub(1)
            .ok_or_else(|| eyre!("runtime Circom instruction limit exceeded"))?;
        Ok(())
    }

    fn call(
        &mut self,
        function: usize,
        arguments: &[Fr],
        argument_layout: Option<&[(RuntimeExpression, usize)]>,
        arena_size: usize,
        result_size: usize,
    ) -> eyre::Result<Vec<Fr>> {
        let function = self
            .functions
            .get(function)
            .ok_or_else(|| eyre!("runtime Circom function {function} is missing"))?;
        if function_name_matches(&function.name, "mod_inv") {
            return evaluate_mod_inv(arguments, result_size);
        }
        if function_name_matches(&function.name, "signed_long_to_short") {
            if let Some(result) = evaluate_signed_long_to_short(arguments, result_size) {
                return result;
            }
        }
        if function_name_matches(&function.name, "get_signed_Fp_carry_witness") {
            if let Some(result) = evaluate_signed_fp_carry(arguments, result_size) {
                return result;
            }
        }
        for (name, specialization) in [
            (
                "long_gt",
                evaluate_long_gt
                    as fn(
                        &[Fr],
                        Option<&[(RuntimeExpression, usize)]>,
                        usize,
                    ) -> Option<eyre::Result<Vec<Fr>>>,
            ),
            ("long_sub", evaluate_long_sub),
            ("long_add", evaluate_long_add),
        ] {
            if function_name_matches(&function.name, name) {
                if let Some(result) = specialization(arguments, argument_layout, result_size) {
                    return result;
                }
                break;
            }
        }
        for (name, specialization) in [
            (
                "long_div2",
                evaluate_long_div2 as fn(&[Fr], usize) -> Option<eyre::Result<Vec<Fr>>>,
            ),
            ("short_div_norm", evaluate_short_div_norm),
            ("long_scalar_mult", evaluate_long_scalar_mult),
            ("SplitFn", evaluate_split),
        ] {
            if function_name_matches(&function.name, name) {
                if let Some(result) = specialization(arguments, result_size) {
                    return result;
                }
                break;
            }
        }
        let mut variables = vec![Fr::from(0_u64); arena_size.max(function.variable_count)];
        if arguments.len() > variables.len() {
            bail!(
                "arguments for runtime Circom function {} exceed its variable arena",
                function.name
            );
        }
        variables[..arguments.len()].copy_from_slice(arguments);
        match self.execute_list(&function.body, &mut variables)? {
            Flow::Return(mut values) => {
                // Circom passes the caller's requested result size to generated
                // functions. Some real-world circuits intentionally assign a
                // shorter returned array to a wider destination; the generated
                // WASM copies the zero-initialized tail in that case.
                values.resize(result_size, Fr::from(0_u64));
                values.truncate(result_size);
                Ok(values)
            }
            Flow::Continue => bail!("runtime Circom function {} did not return", function.name),
        }
    }

    fn execute_list(
        &mut self,
        statements: &[RuntimeStatement],
        variables: &mut [Fr],
    ) -> eyre::Result<Flow> {
        for statement in statements {
            self.step()?;
            match statement {
                RuntimeStatement::Store {
                    offset,
                    size,
                    value,
                } => {
                    let offset = self.evaluate(offset, variables)?.address()?;
                    let value = self.evaluate(value, variables)?.fields()?;
                    if value.len() < *size {
                        bail!("runtime Circom store source is shorter than its declared size");
                    }
                    let end = offset
                        .checked_add(*size)
                        .ok_or_else(|| eyre!("runtime Circom store overflowed"))?;
                    let destination = variables
                        .get_mut(offset..end)
                        .ok_or_else(|| eyre!("runtime Circom store is out of bounds"))?;
                    destination.copy_from_slice(&value[..*size]);
                }
                RuntimeStatement::Call(call) => {
                    self.evaluate(call, variables)?;
                }
                RuntimeStatement::Branch {
                    condition,
                    if_branch,
                    else_branch,
                } => {
                    let condition = self.evaluate(condition, variables)?.fields()?;
                    let branch = if condition
                        .first()
                        .is_some_and(|value| *value != Fr::from(0_u64))
                    {
                        if_branch
                    } else {
                        else_branch
                    };
                    if let Flow::Return(values) = self.execute_list(branch, variables)? {
                        return Ok(Flow::Return(values));
                    }
                }
                RuntimeStatement::Loop { condition, body } => loop {
                    let condition = self.evaluate(condition, variables)?.fields()?;
                    if condition
                        .first()
                        .is_none_or(|value| *value == Fr::from(0_u64))
                    {
                        break;
                    }
                    if let Flow::Return(values) = self.execute_list(body, variables)? {
                        return Ok(Flow::Return(values));
                    }
                },
                RuntimeStatement::Return { value, size } => {
                    let mut values = self.evaluate(value, variables)?.fields()?;
                    values.truncate(*size);
                    return Ok(Flow::Return(values));
                }
            }
        }
        Ok(Flow::Continue)
    }

    fn evaluate(
        &mut self,
        expression: &RuntimeExpression,
        variables: &[Fr],
    ) -> eyre::Result<Value> {
        self.step()?;
        Ok(match expression {
            RuntimeExpression::Field(value) => Value::Fields(vec![Fr::new((*value).into())]),
            RuntimeExpression::Address(value) => Value::Address(*value),
            RuntimeExpression::Load { offset, size } => {
                let offset = self.evaluate(offset, variables)?.address()?;
                let end = offset
                    .checked_add(*size)
                    .ok_or_else(|| eyre!("runtime Circom load overflowed"))?;
                Value::Fields(
                    variables
                        .get(offset..end)
                        .ok_or_else(|| eyre!("runtime Circom load is out of bounds"))?
                        .to_vec(),
                )
            }
            RuntimeExpression::Compute {
                operation,
                operands,
            } => {
                let mut values = Vec::with_capacity(operands.len());
                for operand in operands {
                    values.push(self.evaluate(operand, variables)?);
                }
                match operation {
                    RuntimeOperation::AddAddress | RuntimeOperation::MulAddress => {
                        let mut values = values.into_iter();
                        let left = values.next().unwrap().address()?;
                        let right = values.next().unwrap().address()?;
                        let value = if matches!(operation, RuntimeOperation::AddAddress) {
                            left.checked_add(right)
                        } else {
                            left.checked_mul(right)
                        }
                        .ok_or_else(|| eyre!("runtime Circom address overflowed"))?;
                        Value::Address(value)
                    }
                    RuntimeOperation::ToAddress => {
                        let value: U256 = values.into_iter().next().unwrap().fields()?[0].into();
                        Value::Address(
                            usize::try_from(value)
                                .map_err(|_| eyre!("runtime Circom address does not fit usize"))?,
                        )
                    }
                    RuntimeOperation::Equal(size) => {
                        let mut values = values.into_iter();
                        let left = values.next().unwrap().fields()?;
                        let right = values.next().unwrap().fields()?;
                        if left.len() < *size || right.len() < *size || *size == 0 {
                            bail!("invalid runtime Circom multi-value equality");
                        }
                        Value::Fields(vec![Fr::from(left[..*size] == right[..*size])])
                    }
                    RuntimeOperation::Field(operation) => {
                        let mut values = values.into_iter();
                        let left = values.next().unwrap().fields()?;
                        let a = *left
                            .first()
                            .ok_or_else(|| eyre!("runtime Circom operation has no operand"))?;
                        let b = if let Some(right) = values.next() {
                            *right
                                .fields()?
                                .first()
                                .ok_or_else(|| eyre!("runtime Circom operation has no operand"))?
                        } else {
                            a
                        };
                        Value::Fields(vec![operation.eval_fr(a, b)])
                    }
                }
            }
            RuntimeExpression::Call {
                function,
                arena_size,
                result_size,
                arguments,
            } => {
                let mut flattened = Vec::new();
                for (argument, size) in arguments {
                    let values = self.evaluate(argument, variables)?.fields()?;
                    if values.len() < *size {
                        bail!("runtime Circom call argument is shorter than its declared size");
                    }
                    flattened.extend_from_slice(&values[..*size]);
                }
                Value::Fields(self.call(
                    *function,
                    &flattened,
                    Some(arguments),
                    *arena_size,
                    *result_size,
                )?)
            }
        })
    }
}

fn function_name_matches(actual: &str, expected: &str) -> bool {
    actual == expected
        || actual
            .strip_prefix(expected)
            .and_then(|suffix| suffix.strip_prefix('_'))
            .is_some_and(|suffix| {
                !suffix.is_empty() && suffix.bytes().all(|character| character.is_ascii_digit())
            })
}

fn dimension(value: Fr) -> Option<usize> {
    usize::try_from(BigUint::from(value)).ok()
}

fn limb_width(arguments: &[Fr]) -> Option<(usize, usize)> {
    let n = dimension(*arguments.first()?)?;
    let k = dimension(*arguments.get(1)?)?;
    (n > 0 && n <= 256 && k > 0 && k <= 50).then_some((n, k))
}

fn compose_limbs(limbs: &[Fr], n: usize) -> Option<BigUint> {
    let bound = BigUint::from(1_u8) << n;
    limbs
        .iter()
        .enumerate()
        .try_fold(BigUint::from(0_u8), |value, (index, limb)| {
            let limb = BigUint::from(*limb);
            (limb < bound).then(|| value + (limb << (n * index)))
        })
}

/// Recover the two array operands used by the fixed-width bigint helpers. Nested calls retain
/// their exact Circom argument boundaries. Top-level graph calls currently retain only flattened
/// parameters, so accept only the library's two unambiguous layouts: two `k`-limb values or two
/// 50-limb scratch arrays.
fn two_array_operands<'a>(
    arguments: &'a [Fr],
    argument_layout: Option<&[(RuntimeExpression, usize)]>,
    k: usize,
) -> Option<(&'a [Fr], &'a [Fr])> {
    let (left_width, right_width) = if let Some(argument_layout) = argument_layout {
        if argument_layout.len() != 4
            || argument_layout[0].1 != 1
            || argument_layout[1].1 != 1
            || argument_layout[2].1 < k
            || argument_layout[3].1 < k
            || argument_layout.iter().map(|(_, size)| size).sum::<usize>() != arguments.len()
        {
            return None;
        }
        (argument_layout[2].1, argument_layout[3].1)
    } else if arguments.len() == 2 + 2 * k {
        (k, k)
    } else if k <= 50 && arguments.len() == 2 + 2 * 50 {
        (50, 50)
    } else {
        return None;
    };
    let left_start = 2;
    let right_start = left_start + left_width;
    debug_assert_eq!(right_start + right_width, arguments.len());
    Some((
        &arguments[left_start..left_start + k],
        &arguments[right_start..right_start + k],
    ))
}

fn write_limbs(value: &BigUint, n: usize, output: &mut [Fr]) {
    let mask = (BigUint::from(1_u8) << n) - BigUint::from(1_u8);
    for (index, destination) in output.iter_mut().enumerate() {
        *destination = Fr::from((value >> (n * index)) & &mask);
    }
}

fn balanced_integer(value: Fr) -> BigInt {
    let value: U256 = value.into();
    if value > crate::M >> 1 {
        BigInt::from_biguint(Sign::Minus, BigUint::from(crate::M - value))
    } else {
        BigInt::from_biguint(Sign::Plus, BigUint::from(value))
    }
}

fn compose_balanced_limbs(limbs: &[Fr], n: usize) -> BigInt {
    limbs
        .iter()
        .enumerate()
        .fold(BigInt::from(0_u8), |value, (index, limb)| {
            value + (balanced_integer(*limb) << (n * index))
        })
}

fn write_signed_limbs(value: &BigUint, negative: bool, n: usize, output: &mut [Fr]) {
    write_limbs(value, n, output);
    if negative {
        for limb in output {
            *limb = -*limb;
        }
    }
}

fn evaluate_signed_long_to_short(
    arguments: &[Fr],
    result_size: usize,
) -> Option<eyre::Result<Vec<Fr>>> {
    const MAX_LIMBS: usize = 50;
    let (n, k) = limb_width(arguments)?;
    if result_size != MAX_LIMBS + 1 || arguments.len() < 2 + k {
        return None;
    }

    let value = compose_balanced_limbs(&arguments[2..2 + k], n);
    let negative = value.sign() == Sign::Minus;
    let magnitude = value.magnitude();
    if magnitude >> (n * MAX_LIMBS) != BigUint::from(0_u8) {
        return None;
    }

    let mut output = vec![Fr::from(0_u64); result_size];
    write_signed_limbs(magnitude, negative, n, &mut output[..MAX_LIMBS]);
    if negative {
        output[MAX_LIMBS] = Fr::from(1_u64);
    }
    Some(Ok(output))
}

fn evaluate_signed_fp_carry(arguments: &[Fr], result_size: usize) -> Option<eyre::Result<Vec<Fr>>> {
    const ROW_SIZE: usize = 50;
    let (n, k) = limb_width(arguments)?;
    let m = dimension(*arguments.get(2)?)?;
    if m == 0 || m >= ROW_SIZE || result_size != 2 * ROW_SIZE || arguments.len() != 3 + 2 * k {
        return None;
    }

    let value = compose_balanced_limbs(&arguments[3..3 + k], n);
    let modulus = compose_limbs(&arguments[3 + k..], n)?;
    if modulus == BigUint::from(0_u8) {
        return None;
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
        return None;
    }

    let mut output = vec![Fr::from(0_u64); result_size];
    write_signed_limbs(&quotient, negative, n, &mut output[..m]);
    write_limbs(&remainder, n, &mut output[ROW_SIZE..ROW_SIZE + k]);
    Some(Ok(output))
}

fn evaluate_long_gt(
    arguments: &[Fr],
    argument_layout: Option<&[(RuntimeExpression, usize)]>,
    result_size: usize,
) -> Option<eyre::Result<Vec<Fr>>> {
    let (n, k) = limb_width(arguments)?;
    if result_size != 1 {
        return None;
    }
    let (left, right) = two_array_operands(arguments, argument_layout, k)?;
    let left = compose_limbs(left, n)?;
    let right = compose_limbs(right, n)?;
    Some(Ok(vec![Fr::from(left > right)]))
}

fn evaluate_long_sub(
    arguments: &[Fr],
    argument_layout: Option<&[(RuntimeExpression, usize)]>,
    result_size: usize,
) -> Option<eyre::Result<Vec<Fr>>> {
    let (n, k) = limb_width(arguments)?;
    if result_size < k {
        return None;
    }
    let (left, right) = two_array_operands(arguments, argument_layout, k)?;
    let left = compose_limbs(left, n)?;
    let right = compose_limbs(right, n)?;
    let modulus = BigUint::from(1_u8) << (n * k);
    let difference = if left >= right {
        left - right
    } else {
        modulus + left - right
    };
    let mut output = vec![Fr::from(0_u64); result_size];
    write_limbs(&difference, n, &mut output[..k]);
    Some(Ok(output))
}

fn evaluate_long_add(
    arguments: &[Fr],
    argument_layout: Option<&[(RuntimeExpression, usize)]>,
    result_size: usize,
) -> Option<eyre::Result<Vec<Fr>>> {
    let (n, k) = limb_width(arguments)?;
    if result_size <= k {
        return None;
    }
    let (left, right) = two_array_operands(arguments, argument_layout, k)?;
    let sum = compose_limbs(left, n)? + compose_limbs(right, n)?;
    let mut output = vec![Fr::from(0_u64); result_size];
    write_limbs(&sum, n, &mut output[..k + 1]);
    Some(Ok(output))
}

fn evaluate_split(arguments: &[Fr], result_size: usize) -> Option<eyre::Result<Vec<Fr>>> {
    if arguments.len() != 3 || result_size != 2 {
        return None;
    }
    let n = dimension(arguments[1])?;
    let m = dimension(arguments[2])?;
    if n > 256 || m > 256 || n + m > 256 {
        return None;
    }
    let value = BigUint::from(arguments[0]);
    let low_mask = (BigUint::from(1_u8) << n) - BigUint::from(1_u8);
    let high_mask = (BigUint::from(1_u8) << m) - BigUint::from(1_u8);
    Some(Ok(vec![
        Fr::from(&value & low_mask),
        Fr::from((value >> n) & high_mask),
    ]))
}

fn evaluate_short_div_norm(arguments: &[Fr], result_size: usize) -> Option<eyre::Result<Vec<Fr>>> {
    let (n, k) = limb_width(arguments)?;
    if result_size != 1 {
        return None;
    }
    let (left_width, right_width) = if arguments.len() == 2 + (k + 1) + k {
        (k + 1, k)
    } else if k < 50 && arguments.len() == 2 + 2 * 50 {
        (50, 50)
    } else {
        return None;
    };
    let right_start = 2 + left_width;
    debug_assert_eq!(right_start + right_width, arguments.len());
    let dividend = compose_limbs(&arguments[2..2 + k + 1], n)?;
    let divisor = compose_limbs(&arguments[right_start..right_start + k], n)?;
    if divisor == BigUint::from(0_u8) {
        return None;
    }
    let quotient = dividend / divisor;
    if quotient >= (BigUint::from(1_u8) << n) {
        return None;
    }
    Some(Ok(vec![Fr::from(quotient)]))
}

fn evaluate_long_scalar_mult(
    arguments: &[Fr],
    result_size: usize,
) -> Option<eyre::Result<Vec<Fr>>> {
    let (n, k) = limb_width(arguments)?;
    if arguments.len() < 3 + k || result_size < k + 1 {
        return None;
    }
    let scalar = BigUint::from(arguments[2]);
    let limb_bound = BigUint::from(1_u8) << n;
    if scalar >= limb_bound {
        return None;
    }
    let operand = compose_limbs(&arguments[3..3 + k], n)?;
    let product = scalar * operand;
    let mask = limb_bound - BigUint::from(1_u8);
    let mut output = vec![Fr::from(0_u64); result_size];
    for (index, destination) in output[..k + 1].iter_mut().enumerate() {
        *destination = Fr::from((&product >> (n * index)) & &mask);
    }
    Some(Ok(output))
}

/// Native specialization of the fixed-width long division used by circom-pairing and
/// circom-ecdsa. The Circom implementation performs Knuth-style division one limb at a time and
/// dominates WebAuthn witness generation when interpreted. Its return type is always `var[2][50]`:
/// the first row contains the quotient and the second the remainder.
///
/// Circom specializes array arguments at each call site. The dividend may therefore carry a
/// zero-initialized tail between its `k + m` significant limbs and the final `k`-limb divisor. The
/// divisor is the final argument, which lets this specialization accept all observed call-site
/// widths without encoding a circuit-specific arena layout.
fn evaluate_long_div2(arguments: &[Fr], result_size: usize) -> Option<eyre::Result<Vec<Fr>>> {
    const ROW_SIZE: usize = 50;
    if arguments.len() < 3 || result_size != 2 * ROW_SIZE {
        return None;
    }

    let n = dimension(arguments[0])?;
    let k = dimension(arguments[1])?;
    let m = dimension(arguments[2])?;
    if n == 0
        || n > 256
        || k == 0
        || k > ROW_SIZE
        || m >= ROW_SIZE
        || k + m >= ROW_SIZE
        || arguments.len() < 3 + k + m + k
    {
        return None;
    }

    let divisor_start = arguments.len() - k;
    if divisor_start < 3 + k + m {
        return None;
    }
    let dividend_limbs = &arguments[3..3 + k + m];
    let divisor_limbs = &arguments[divisor_start..];
    let limb_bound = BigUint::from(1_u8) << n;
    if dividend_limbs
        .iter()
        .chain(divisor_limbs)
        .any(|limb| BigUint::from(*limb) >= limb_bound)
        || divisor_limbs[k - 1] == Fr::from(0_u64)
    {
        return None;
    }

    let compose = |limbs: &[Fr]| {
        limbs
            .iter()
            .enumerate()
            .fold(BigUint::from(0_u8), |value, (index, limb)| {
                value + (BigUint::from(*limb) << (n * index))
            })
    };
    let dividend = compose(dividend_limbs);
    let divisor = compose(divisor_limbs);
    if divisor == BigUint::from(0_u8) {
        return Some(Err(eyre!("Circom long_div2 divisor is zero")));
    }

    let quotient = &dividend / &divisor;
    let remainder = dividend % divisor;
    if (&quotient >> (n * (m + 1))) != BigUint::from(0_u8)
        || (&remainder >> (n * k)) != BigUint::from(0_u8)
    {
        return Some(Err(eyre!(
            "Circom long_div2 result exceeds its limb bounds"
        )));
    }

    let mask = &limb_bound - BigUint::from(1_u8);
    let mut output = vec![Fr::from(0_u64); result_size];
    for (index, destination) in output[..m + 1].iter_mut().enumerate() {
        *destination = Fr::from((&quotient >> (n * index)) & &mask);
    }
    for (index, destination) in output[ROW_SIZE..ROW_SIZE + k].iter_mut().enumerate() {
        *destination = Fr::from((&remainder >> (n * index)) & &mask);
    }
    Some(Ok(output))
}

fn evaluate_mod_inv(arguments: &[Fr], result_size: usize) -> eyre::Result<Vec<Fr>> {
    if arguments.len() < 2 {
        bail!("Circom mod_inv call is missing n and k");
    }
    let n = usize::try_from(BigUint::from(arguments[0]))
        .map_err(|_| eyre!("Circom mod_inv limb width does not fit usize"))?;
    let k = usize::try_from(BigUint::from(arguments[1]))
        .map_err(|_| eyre!("Circom mod_inv limb count does not fit usize"))?;
    if n == 0 || n > 256 || arguments.len() < 2 + 2 * k {
        bail!("Circom mod_inv has invalid limb dimensions");
    }

    let compose = |limbs: &[Fr]| {
        limbs
            .iter()
            .enumerate()
            .fold(BigUint::from(0_u8), |value, (index, limb)| {
                value + (BigUint::from(*limb) << (n * index))
            })
    };
    let value = compose(&arguments[2..2 + k]);
    // Circom specializes array parameters at each call site. The bigint
    // library uses either k, 50, or 100 slots for the first operand, while
    // only the first k slots carry limbs. Recover the second parameter's
    // boundary and prefer the nonzero modulus candidate.
    let modulus = [k, 50, 100]
        .into_iter()
        .filter(|operand_size| arguments.len() >= 2 + operand_size + k)
        .map(|operand_size| compose(&arguments[2 + operand_size..2 + operand_size + k]))
        .max()
        .unwrap_or_default();
    if modulus <= BigUint::from(2_u8) {
        bail!("Circom mod_inv modulus must be greater than two");
    }
    let inverse = if value == BigUint::from(0_u8) {
        value
    } else {
        value.modpow(&(&modulus - BigUint::from(2_u8)), &modulus)
    };
    let mask = (BigUint::from(1_u8) << n) - BigUint::from(1_u8);
    let mut output = Vec::with_capacity(result_size);
    for index in 0..result_size {
        output.push(if index < k {
            Fr::from((&inverse >> (n * index)) & &mask)
        } else {
            Fr::from(0_u64)
        });
    }
    Ok(output)
}

pub(crate) fn evaluate(
    functions: &[RuntimeFunction],
    function: usize,
    arguments: &[Fr],
    arena_size: usize,
    result_size: usize,
) -> eyre::Result<Vec<Fr>> {
    Interpreter {
        functions,
        steps_left: 100_000_000,
    }
    .call(function, arguments, None, arena_size, result_size)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load(offset: usize) -> RuntimeExpression {
        RuntimeExpression::Load {
            offset: Box::new(RuntimeExpression::Address(offset)),
            size: 1,
        }
    }

    fn compute(
        operation: Operation,
        left: RuntimeExpression,
        right: RuntimeExpression,
    ) -> RuntimeExpression {
        RuntimeExpression::Compute {
            operation: RuntimeOperation::Field(operation),
            operands: vec![left, right],
        }
    }

    #[test]
    fn runtime_loop_uses_input_dependent_control_flow() {
        let function = RuntimeFunction {
            name: "sum_to_n".to_owned(),
            variable_count: 2,
            body: vec![
                RuntimeStatement::Loop {
                    condition: load(0),
                    body: vec![
                        RuntimeStatement::Store {
                            offset: RuntimeExpression::Address(1),
                            size: 1,
                            value: compute(Operation::Add, load(1), load(0)),
                        },
                        RuntimeStatement::Store {
                            offset: RuntimeExpression::Address(0),
                            size: 1,
                            value: compute(
                                Operation::Sub,
                                load(0),
                                RuntimeExpression::Field(U256::from(1_u64)),
                            ),
                        },
                    ],
                },
                RuntimeStatement::Return {
                    value: load(1),
                    size: 1,
                },
            ],
        };

        assert_eq!(
            evaluate(&[function], 0, &[Fr::from(4_u64)], 2, 1).unwrap(),
            vec![Fr::from(10_u64)]
        );
    }

    #[test]
    fn bigint_mod_inv_specialization_uses_circom_limbs_and_zero_extends() {
        let function = RuntimeFunction {
            name: "mod_inv_22".to_owned(),
            variable_count: 0,
            body: Vec::new(),
        };
        let arguments = [4_u64, 2, 3, 0, 13, 0].map(Fr::from);

        assert_eq!(
            evaluate(&[function], 0, &arguments, 0, 4).unwrap(),
            vec![
                Fr::from(9_u64),
                Fr::from(0_u64),
                Fr::from(0_u64),
                Fr::from(0_u64),
            ]
        );
    }

    #[test]
    fn bigint_long_div2_specialization_uses_native_quotient_and_remainder() {
        let function = RuntimeFunction {
            name: "long_div2_43".to_owned(),
            variable_count: 0,
            body: Vec::new(),
        };
        // Base 16: 0x345 / 0x11 = 0x31, remainder 0x4. The dividend carries the same
        // zero-initialized padding between operands that Circom emits for WebAuthn calls.
        let arguments = [
            4_u64, 2, 1, // n, k, m
            5, 4, 3, // dividend limbs
            0, 0, // padded dividend tail
            1, 1, // divisor limbs
        ]
        .map(Fr::from);

        let result = evaluate(&[function], 0, &arguments, 0, 100).unwrap();
        assert_eq!(result[0], Fr::from(1_u64));
        assert_eq!(result[1], Fr::from(3_u64));
        assert!(result[2..50].iter().all(|value| *value == Fr::from(0_u64)));
        assert_eq!(result[50], Fr::from(4_u64));
        assert_eq!(result[51], Fr::from(0_u64));
        assert!(result[52..].iter().all(|value| *value == Fr::from(0_u64)));
    }

    #[test]
    fn bigint_short_division_specialization_uses_normalized_limbs() {
        let function = RuntimeFunction {
            name: "short_div_norm_60".to_owned(),
            variable_count: 0,
            body: Vec::new(),
        };
        // Base 16: 0x123 / 0x9a = 1. Both operands occupy 50-limb scratch arrays, so
        // the divisor starts at the second array boundary rather than at the end.
        let mut arguments = vec![Fr::from(4_u64), Fr::from(2_u64)];
        arguments.extend([3_u64, 2, 1].map(Fr::from));
        arguments.resize(52, Fr::from(0_u64));
        arguments.extend([10_u64, 9].map(Fr::from));
        arguments.resize(102, Fr::from(0_u64));

        assert_eq!(
            evaluate(&[function], 0, &arguments, 0, 1).unwrap(),
            vec![Fr::from(1_u64)]
        );
    }

    #[test]
    fn bigint_comparison_addition_and_subtraction_use_padded_array_boundaries() {
        let functions = ["long_gt_53", "long_sub_42", "long_add_45"].map(|name| RuntimeFunction {
            name: name.to_owned(),
            variable_count: 0,
            body: Vec::new(),
        });
        // Base 16: left = 0x21 and right = 0x1f. Each occupies a 50-limb array.
        let mut arguments = vec![Fr::from(4_u64), Fr::from(2_u64)];
        arguments.extend([1_u64, 2].map(Fr::from));
        arguments.resize(52, Fr::from(0_u64));
        arguments.extend([15_u64, 1].map(Fr::from));
        arguments.resize(102, Fr::from(0_u64));

        assert_eq!(
            evaluate(&functions, 0, &arguments, 0, 1).unwrap(),
            vec![Fr::from(1_u64)]
        );
        let difference = evaluate(&functions, 1, &arguments, 0, 50).unwrap();
        assert_eq!(difference[0], Fr::from(2_u64));
        assert!(difference[1..]
            .iter()
            .all(|value| *value == Fr::from(0_u64)));
        let sum = evaluate(&functions, 2, &arguments, 0, 50).unwrap();
        assert_eq!(
            sum[..3],
            [Fr::from(0_u64), Fr::from(4_u64), Fr::from(0_u64)]
        );
        assert!(sum[3..].iter().all(|value| *value == Fr::from(0_u64)));
    }

    #[test]
    fn signed_bigint_specializations_preserve_balanced_limbs_and_euclidean_remainder() {
        let functions = ["signed_long_to_short_35", "get_signed_Fp_carry_witness_7"].map(|name| {
            RuntimeFunction {
                name: name.to_owned(),
                variable_count: 0,
                body: Vec::new(),
            }
        });
        // In base 16, limbs [-4, -1] represent -20.
        let signed_arguments = [
            Fr::from(4_u64),
            Fr::from(2_u64),
            -Fr::from(4_u64),
            -Fr::from(1_u64),
        ];
        let normalized = evaluate(&functions, 0, &signed_arguments, 0, 51).unwrap();
        assert_eq!(normalized[0], -Fr::from(4_u64));
        assert_eq!(normalized[1], -Fr::from(1_u64));
        assert!(normalized[2..50]
            .iter()
            .all(|value| *value == Fr::from(0_u64)));
        assert_eq!(normalized[50], Fr::from(1_u64));

        // -20 = (-2 * 13) + 6, with a non-negative Euclidean remainder.
        let carry_arguments = [
            Fr::from(4_u64),
            Fr::from(2_u64),
            Fr::from(1_u64),
            -Fr::from(4_u64),
            -Fr::from(1_u64),
            Fr::from(13_u64),
            Fr::from(0_u64),
        ];
        let carry = evaluate(&functions, 1, &carry_arguments, 0, 100).unwrap();
        assert_eq!(carry[0], -Fr::from(2_u64));
        assert!(carry[1..50].iter().all(|value| *value == Fr::from(0_u64)));
        assert_eq!(carry[50], Fr::from(6_u64));
        assert!(carry[51..].iter().all(|value| *value == Fr::from(0_u64)));
    }

    #[test]
    fn bigint_scalar_multiplication_specialization_uses_leading_array_limbs() {
        let function = RuntimeFunction {
            name: "long_scalar_mult_59".to_owned(),
            variable_count: 0,
            body: Vec::new(),
        };
        // Base 16: 3 * 0x21 = 0x63. Circom passes the complete 50-limb array, but only
        // the leading k limbs participate in this specialization.
        let mut arguments = vec![Fr::from(4_u64), Fr::from(2_u64), Fr::from(3_u64)];
        arguments.extend([Fr::from(1_u64), Fr::from(2_u64)]);
        arguments.resize(53, Fr::from(0_u64));

        let result = evaluate(&[function], 0, &arguments, 0, 50).unwrap();
        assert_eq!(result[0], Fr::from(3_u64));
        assert_eq!(result[1], Fr::from(6_u64));
        assert!(result[2..].iter().all(|value| *value == Fr::from(0_u64)));
    }

    #[test]
    fn bigint_split_specialization_uses_integer_bit_ranges() {
        let function = RuntimeFunction {
            name: "SplitFn_2".to_owned(),
            variable_count: 0,
            body: Vec::new(),
        };
        let arguments = [0xabc_u64, 4, 8].map(Fr::from);

        assert_eq!(
            evaluate(&[function], 0, &arguments, 0, 2).unwrap(),
            vec![Fr::from(0xc_u64), Fr::from(0xab_u64)]
        );
    }

    #[test]
    fn native_specializations_only_match_numeric_circom_suffixes() {
        assert!(function_name_matches("long_div2", "long_div2"));
        assert!(function_name_matches("long_div2_36", "long_div2"));
        assert!(!function_name_matches("long_div2_helper", "long_div2"));
        assert!(!function_name_matches("long_sub_mod_10", "long_sub"));
    }
}
