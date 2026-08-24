//! Portable interpreter for the small parts of Circom witness code that cannot be represented by
//! a static arithmetic graph (input-dependent branches, loops, or array indexes).

use ark_bn254::Fr;
use eyre::{bail, eyre, Context as _};
use ruint::aliases::U256;
use serde::{Deserialize, Serialize};

use crate::{
    custom::{NativeRuntimeFunction, NativeRuntimeOutcome, RuntimeCallInfo},
    graph::Operation,
    profile::{ProfileCollector, ProfileFrame},
};

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
    native_functions: &'a [NativeRuntimeFunction],
    native_bindings: &'a [Vec<usize>],
    profile: Option<&'a mut ProfileCollector>,
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
        function_id: usize,
        arguments: &[Fr],
        argument_sizes: &[usize],
        arena_size: usize,
        result_size: usize,
    ) -> eyre::Result<Vec<Fr>> {
        if self.profile.is_none() {
            return self.call_inner(
                function_id,
                arguments,
                argument_sizes,
                arena_size,
                result_size,
            );
        }
        let function_name = self
            .functions
            .get(function_id)
            .ok_or_else(|| eyre!("runtime Circom function {function_id} is missing"))?
            .name
            .clone();
        let profile_token = self.profile.as_deref_mut().map(|profile| {
            profile.enter(ProfileFrame::runtime_function(function_id, &function_name))
        });
        let result = self.call_inner(
            function_id,
            arguments,
            argument_sizes,
            arena_size,
            result_size,
        );
        if let Some(token) = profile_token {
            self.profile.as_deref_mut().unwrap().exit(token);
        }
        result
    }

    fn call_inner(
        &mut self,
        function_id: usize,
        arguments: &[Fr],
        argument_sizes: &[usize],
        arena_size: usize,
        result_size: usize,
    ) -> eyre::Result<Vec<Fr>> {
        let mut outputs = vec![Fr::from(0_u64); result_size];
        self.call_inner_into(
            function_id,
            arguments,
            argument_sizes,
            arena_size,
            &mut outputs,
        )?;
        Ok(outputs)
    }

    fn call_into(
        &mut self,
        function_id: usize,
        arguments: &[Fr],
        argument_sizes: &[usize],
        arena_size: usize,
        outputs: &mut [Fr],
    ) -> eyre::Result<()> {
        if self.profile.is_none() {
            return self.call_inner_into(
                function_id,
                arguments,
                argument_sizes,
                arena_size,
                outputs,
            );
        }
        let function_name = self
            .functions
            .get(function_id)
            .ok_or_else(|| eyre!("runtime Circom function {function_id} is missing"))?
            .name
            .clone();
        let profile_token = self.profile.as_deref_mut().map(|profile| {
            profile.enter(ProfileFrame::runtime_function(function_id, &function_name))
        });
        let result =
            self.call_inner_into(function_id, arguments, argument_sizes, arena_size, outputs);
        if let Some(token) = profile_token {
            self.profile.as_deref_mut().unwrap().exit(token);
        }
        result
    }

    fn call_inner_into(
        &mut self,
        function_id: usize,
        arguments: &[Fr],
        argument_sizes: &[usize],
        arena_size: usize,
        outputs: &mut [Fr],
    ) -> eyre::Result<()> {
        let result_size = outputs.len();
        let function = self
            .functions
            .get(function_id)
            .ok_or_else(|| eyre!("runtime Circom function {function_id} is missing"))?;
        let argument_count = argument_sizes
            .iter()
            .try_fold(0_usize, |total, size| total.checked_add(*size));
        if argument_count != Some(arguments.len()) {
            bail!(
                "arguments for runtime Circom function {} do not match their declared boundaries",
                function.name
            );
        }
        let call = RuntimeCallInfo::new(
            function_id,
            &function.name,
            arguments,
            argument_sizes,
            arena_size,
            result_size,
        );
        let native_bindings = self
            .native_bindings
            .get(function_id)
            .map(Vec::as_slice)
            .unwrap_or_default();
        for &native in native_bindings {
            let native = &self.native_functions[native];
            outputs.fill(Fr::from(0_u64));
            let profile_token = self.profile.as_deref_mut().map(|profile| {
                profile.enter(ProfileFrame::native_runtime_handler(format!(
                    "native_runtime:{}",
                    native.name()
                )))
            });
            let result = native
                .evaluate(call, outputs)
                .wrap_err_with(|| format!("native runtime function {:?} failed", native.name()));
            if let Some(token) = profile_token {
                self.profile.as_deref_mut().unwrap().exit(token);
            }
            match result? {
                NativeRuntimeOutcome::Handled => return Ok(()),
                NativeRuntimeOutcome::Fallback => {}
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
            Flow::Return(values) => {
                // Circom passes the caller's requested result size to generated
                // functions. Some real-world circuits intentionally assign a
                // shorter returned array to a wider destination; the generated
                // WASM copies the zero-initialized tail in that case.
                outputs.fill(Fr::from(0_u64));
                let copied = values.len().min(result_size);
                outputs[..copied].copy_from_slice(&values[..copied]);
                Ok(())
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
                let mut argument_sizes = Vec::with_capacity(arguments.len());
                for (argument, size) in arguments {
                    let values = self.evaluate(argument, variables)?.fields()?;
                    if values.len() < *size {
                        bail!("runtime Circom call argument is shorter than its declared size");
                    }
                    argument_sizes.push(*size);
                    flattened.extend_from_slice(&values[..*size]);
                }
                Value::Fields(self.call(
                    *function,
                    &flattened,
                    &argument_sizes,
                    *arena_size,
                    *result_size,
                )?)
            }
        })
    }
}

pub(crate) struct RuntimeInvocation<'a> {
    pub(crate) function: usize,
    pub(crate) arguments: &'a [Fr],
    pub(crate) argument_sizes: &'a [usize],
    pub(crate) arena_size: usize,
    pub(crate) result_size: usize,
}

pub(crate) fn evaluate(
    functions: &[RuntimeFunction],
    native_functions: &[NativeRuntimeFunction],
    native_bindings: &[Vec<usize>],
    profile: Option<&mut ProfileCollector>,
    invocation: RuntimeInvocation<'_>,
) -> eyre::Result<Vec<Fr>> {
    Interpreter {
        functions,
        native_functions,
        native_bindings,
        profile,
        steps_left: 100_000_000,
    }
    .call(
        invocation.function,
        invocation.arguments,
        invocation.argument_sizes,
        invocation.arena_size,
        invocation.result_size,
    )
}

pub(crate) fn evaluate_into(
    functions: &[RuntimeFunction],
    native_functions: &[NativeRuntimeFunction],
    native_bindings: &[Vec<usize>],
    profile: Option<&mut ProfileCollector>,
    invocation: RuntimeInvocation<'_>,
    outputs: &mut [Fr],
) -> eyre::Result<()> {
    if outputs.len() != invocation.result_size {
        bail!("runtime Circom output buffer has the wrong size");
    }
    Interpreter {
        functions,
        native_functions,
        native_bindings,
        profile,
        steps_left: 100_000_000,
    }
    .call_into(
        invocation.function,
        invocation.arguments,
        invocation.argument_sizes,
        invocation.arena_size,
        outputs,
    )
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
            evaluate(
                &[function],
                &[],
                &[],
                None,
                RuntimeInvocation {
                    function: 0,
                    arguments: &[Fr::from(4_u64)],
                    argument_sizes: &[1],
                    arena_size: 2,
                    result_size: 1,
                },
            )
            .unwrap(),
            vec![Fr::from(10_u64)]
        );
    }
}
