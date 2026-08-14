//! Portable interpreter for the small parts of Circom witness code that cannot be represented by
//! a static arithmetic graph (input-dependent branches, loops, or array indexes).

use ark_bn254::Fr;
use eyre::{bail, eyre};
use num_bigint::BigUint;
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
        arena_size: usize,
        result_size: usize,
    ) -> eyre::Result<Vec<Fr>> {
        let function = self
            .functions
            .get(function)
            .ok_or_else(|| eyre!("runtime Circom function {function} is missing"))?;
        if function.name == "mod_inv" || function.name.starts_with("mod_inv_") {
            return evaluate_mod_inv(arguments, result_size);
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
                Value::Fields(self.call(*function, &flattened, *arena_size, *result_size)?)
            }
        })
    }
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
    .call(function, arguments, arena_size, result_size)
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
}
