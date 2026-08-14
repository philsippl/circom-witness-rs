// SPDX-License-Identifier: GPL-3.0-only

use std::{
    collections::{HashMap, HashSet},
    env, fmt,
    path::{Path, PathBuf},
};

use circom_compiler::{
    compiler_interface::{self, Circuit, Config},
    intermediate_representation::ir_interface::{
        AccessType, AddressType, CallBucket, ComputeBucket, CreateCmpBucket, InputInformation,
        InstrContext, Instruction, InstructionList, LocationRule, OperatorType, ReturnType,
        SizeOption, StatusInput, StoreBucket, ValueType,
    },
};
use circom_constraint_generation::{build_circuit, BuildConfig};
use eyre::{bail, eyre, Context as _, Result};
use rand::Rng as _;
use ruint::aliases::U256;

use circom_witness_rs::{
    graph::{self, Node, Operation},
    runtime::{RuntimeExpression, RuntimeFunction, RuntimeOperation, RuntimeStatement},
    serialize_graph_with_runtime, HashSignalInfo, M,
};

const CIRCOM_VERSION: &str = "2.2.2";

#[derive(Default)]
struct GraphBuilder {
    nodes: Vec<Node>,
    values: Vec<U256>,
    constant: Vec<bool>,
    next_runtime_call: usize,
}

#[derive(Debug)]
struct NeedsRuntime;

impl fmt::Display for NeedsRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Circom control flow or an array index depends on an input signal")
    }
}

impl std::error::Error for NeedsRuntime {}

impl GraphBuilder {
    fn push(&mut self, node: Node, value: U256, constant: bool) -> usize {
        let index = self.nodes.len();
        self.nodes.push(node);
        self.values.push(value);
        self.constant.push(constant);
        index
    }

    fn constant(&mut self, value: U256) -> usize {
        self.push(Node::Constant(value), value, true)
    }

    fn input(&mut self, signal: usize) -> usize {
        self.push(Node::Input(signal), U256::ZERO, false)
    }

    fn op(&mut self, operation: Operation, a: usize, b: usize) -> usize {
        let constant = self.constant[a] && self.constant[b];
        let value = if constant {
            operation.eval(self.values[a], self.values[b])
        } else {
            rand::thread_rng().gen::<U256>() % M
        };
        self.push(Node::Op(operation, a, b), value, constant)
    }

    fn black_box(&mut self, name: String, params: Vec<usize>) -> usize {
        let value = rand::thread_rng().gen::<U256>() % M;
        self.push(Node::BBF(name, params), value, false)
    }

    fn runtime_call(
        &mut self,
        function: usize,
        params: Vec<usize>,
        arena_size: usize,
        output_count: usize,
    ) -> Vec<usize> {
        let call = self.next_runtime_call;
        self.next_runtime_call += 1;
        (0..output_count)
            .map(|output| {
                let value = rand::thread_rng().gen::<U256>() % M;
                self.push(
                    Node::RuntimeCall {
                        function,
                        call,
                        output,
                        output_count,
                        arena_size,
                        parameters: params.clone(),
                    },
                    value,
                    false,
                )
            })
            .collect()
    }

    fn constant_value(&self, node: usize) -> Result<U256> {
        if self.constant[node] {
            Ok(self.values[node])
        } else {
            Err(NeedsRuntime.into())
        }
    }
}

#[derive(Clone)]
struct Component {
    template_id: usize,
    signal_start: usize,
    input_counter: usize,
    subcomponents: Vec<Option<usize>>,
    ran: bool,
}

struct Frame {
    component: usize,
    variables: Vec<Option<usize>>,
    is_function: bool,
}

enum Eval {
    Address(usize),
    Values {
        nodes: Vec<usize>,
        component: Option<usize>,
    },
}

impl Eval {
    fn address(self) -> Result<usize> {
        match self {
            Self::Address(value) => Ok(value),
            Self::Values { .. } => bail!("expected a Circom address expression"),
        }
    }

    fn values(self) -> Result<(Vec<usize>, Option<usize>)> {
        match self {
            Self::Values { nodes, component } => Ok((nodes, component)),
            Self::Address(_) => bail!("expected a Circom field expression"),
        }
    }
}

enum Memory {
    Variables,
    Signals,
}

struct Place {
    memory: Memory,
    offset: usize,
    component: Option<usize>,
}

enum Flow {
    Continue,
    Return(Vec<usize>),
}

type TemplateBranchSide = (Flow, Vec<Option<usize>>, HashMap<usize, Option<usize>>);

struct Interpreter<'a> {
    circuit: &'a Circuit,
    graph: GraphBuilder,
    constants: Vec<usize>,
    signals: Vec<Option<usize>>,
    components: Vec<Option<Component>>,
    runtime_functions: Vec<Option<RuntimeFunction>>,
    runtime_function_ids: HashMap<(String, usize), usize>,
    signal_undos: Vec<HashMap<usize, Option<usize>>>,
    zero: usize,
}

impl<'a> Interpreter<'a> {
    fn new(circuit: &'a Circuit) -> Result<Self> {
        let producer = &circuit.c_producer;
        if producer.prime_str != "bn128" {
            bail!(
                "only Circom's bn128 field is supported, got {}",
                producer.prime_str
            );
        }

        let mut graph = GraphBuilder::default();
        let zero = graph.constant(U256::ZERO);
        let mut signals = vec![Some(zero); producer.total_number_of_signals];
        signals[0] = Some(graph.constant(U256::ONE));

        let main_input_start = producer.get_number_of_main_outputs();
        for (signal, slot) in signals
            .iter_mut()
            .enumerate()
            .skip(main_input_start)
            .take(producer.number_of_main_inputs)
        {
            *slot = Some(graph.input(signal));
        }

        let constants = producer
            .field_tracking
            .iter()
            .map(|value| parse_field_constant(value).map(|value| graph.constant(value)))
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            circuit,
            graph,
            constants,
            signals,
            components: vec![None; producer.number_of_components],
            runtime_functions: Vec::new(),
            runtime_function_ids: HashMap::new(),
            signal_undos: Vec::new(),
            zero,
        })
    }

    fn build(mut self) -> Result<(Vec<Node>, Vec<usize>, Vec<RuntimeFunction>)> {
        let main_template = self
            .circuit
            .templates
            .iter()
            .find(|template| template.header == self.circuit.c_producer.main_header)
            .ok_or_else(|| eyre!("Circom main template was not found"))?;
        self.components[0] = Some(Component {
            template_id: main_template.id,
            signal_start: self.circuit.c_producer.main_signal_offset,
            input_counter: main_template.number_of_inputs,
            subcomponents: vec![None; main_template.number_of_components],
            ran: false,
        });
        self.run_template(0)?;

        let outputs = self
            .circuit
            .c_producer
            .witness_to_signal_list
            .iter()
            .map(|&signal| {
                self.signals[signal]
                    .ok_or_else(|| eyre!("witness signal {signal} was not assigned by Circom"))
            })
            .collect::<Result<Vec<_>>>()?;
        let runtime_functions = self
            .runtime_functions
            .into_iter()
            .enumerate()
            .map(|(index, function)| {
                function.ok_or_else(|| eyre!("runtime Circom function {index} was not compiled"))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok((self.graph.nodes, outputs, runtime_functions))
    }

    fn run_template(&mut self, component_id: usize) -> Result<()> {
        let component = self.component(component_id)?.clone();
        if component.ran {
            bail!("Circom component {component_id} was executed more than once");
        }
        self.component_mut(component_id)?.ran = true;

        let circuit = self.circuit;
        let template = circuit.get_template(component.template_id);
        let mut frame = Frame {
            component: component_id,
            variables: vec![Some(self.zero); template.var_stack_depth],
            is_function: false,
        };
        match self
            .execute_list(&template.body, &mut frame)
            .wrap_err_with(|| {
                format!(
                    "while symbolically executing Circom template {} (component {component_id})",
                    template.header
                )
            })? {
            Flow::Continue => Ok(()),
            Flow::Return(_) => bail!("Circom template {} returned a value", template.header),
        }
    }

    fn execute_function(
        &mut self,
        symbol: &str,
        arguments: Vec<usize>,
        arena_size: usize,
        component: usize,
        result_size: usize,
    ) -> Result<Vec<usize>> {
        let circuit = self.circuit;
        let function = circuit
            .functions
            .iter()
            .find(|function| function.header == symbol)
            .ok_or_else(|| eyre!("Circom function {symbol} was not found"))?;
        let mut variables = vec![Some(self.zero); arena_size.max(function.max_number_of_vars)];
        if arguments.len() > variables.len() {
            bail!("arguments for Circom function {symbol} exceed its variable arena");
        }
        for (slot, value) in variables.iter_mut().zip(arguments) {
            *slot = Some(value);
        }
        let mut frame = Frame {
            component,
            variables,
            is_function: true,
        };
        match self
            .execute_list(&function.body, &mut frame)
            .wrap_err_with(|| format!("while symbolically executing Circom function {symbol}"))?
        {
            Flow::Return(mut values) => {
                values.truncate(result_size);
                Ok(values)
            }
            Flow::Continue => bail!("Circom function {symbol} did not return a value"),
        }
    }

    fn execute_function_or_runtime(
        &mut self,
        symbol: &str,
        arguments: Vec<usize>,
        arena_size: usize,
        component: usize,
        result_size: usize,
    ) -> Result<Vec<usize>> {
        let checkpoint = self.graph.nodes.len();
        match self.execute_function(
            symbol,
            arguments.clone(),
            arena_size,
            component,
            result_size,
        ) {
            Ok(values) => Ok(values),
            Err(error) if error.downcast_ref::<NeedsRuntime>().is_some() => {
                self.graph.nodes.truncate(checkpoint);
                self.graph.values.truncate(checkpoint);
                self.graph.constant.truncate(checkpoint);
                let function = self.compile_runtime_function(symbol, component)?;
                Ok(self
                    .graph
                    .runtime_call(function, arguments, arena_size, result_size))
            }
            Err(error) => Err(error),
        }
    }

    fn execute_list(&mut self, body: &InstructionList, frame: &mut Frame) -> Result<Flow> {
        for instruction in body {
            match instruction.as_ref() {
                Instruction::Store(store) => self.execute_store(store, frame)?,
                Instruction::Call(call) => {
                    self.execute_call(call, frame)?;
                }
                Instruction::Branch(branch) => {
                    let condition = self.eval_condition_node(branch.cond.as_ref(), frame)?;
                    if self.graph.constant[condition] {
                        let body = if self.graph.values[condition] != U256::ZERO {
                            &branch.if_branch
                        } else {
                            &branch.else_branch
                        };
                        if let Flow::Return(values) = self.execute_list(body, frame)? {
                            return Ok(Flow::Return(values));
                        }
                    } else if frame.is_function {
                        return Err(NeedsRuntime.into());
                    } else {
                        self.execute_dynamic_template_branch(
                            condition,
                            &branch.if_branch,
                            &branch.else_branch,
                            frame,
                        )?;
                    }
                }
                Instruction::Loop(loop_bucket) => {
                    while self.eval_condition(loop_bucket.continue_condition.as_ref(), frame)? {
                        if let Flow::Return(values) = self.execute_list(&loop_bucket.body, frame)? {
                            return Ok(Flow::Return(values));
                        }
                    }
                }
                Instruction::Return(return_bucket) => {
                    let (mut values, _) =
                        self.eval(return_bucket.value.as_ref(), frame)?.values()?;
                    values.truncate(return_bucket.with_size);
                    return Ok(Flow::Return(values));
                }
                Instruction::CreateCmp(create) => self.create_components(create, frame)?,
                // The old bridge removed generated assertions and trace statements too.
                Instruction::Assert(_) | Instruction::Log(_) => {}
                Instruction::Value(_) | Instruction::Load(_) | Instruction::Compute(_) => {
                    self.eval(instruction.as_ref(), frame)?;
                }
            }
        }
        Ok(Flow::Continue)
    }

    fn eval(&mut self, instruction: &Instruction, frame: &mut Frame) -> Result<Eval> {
        match instruction {
            Instruction::Value(value) => match value.parse_as {
                ValueType::U32 => Ok(Eval::Address(value.value)),
                ValueType::BigInt => Ok(Eval::Values {
                    nodes: vec![self.constants[value.value]],
                    component: None,
                }),
            },
            Instruction::Load(load) => {
                let place = self.resolve_place(&load.address_type, &load.src, frame)?;
                let size = self.resolve_size(&load.context, place.component)?;
                let nodes = self.read_place(&place, size, frame)?;
                Ok(Eval::Values {
                    nodes,
                    component: place.component,
                })
            }
            Instruction::Compute(compute) => self.eval_compute(compute, frame),
            Instruction::Call(call) => self
                .execute_call(call, frame)?
                .ok_or_else(|| eyre!("a final Circom call cannot be used as an expression")),
            _ => bail!("Circom statement cannot be evaluated as an expression"),
        }
    }

    fn eval_compute(&mut self, compute: &ComputeBucket, frame: &mut Frame) -> Result<Eval> {
        let mut operands = Vec::with_capacity(compute.stack.len());
        for operand in &compute.stack {
            operands.push(self.eval(operand.as_ref(), frame)?);
        }

        use OperatorType::*;
        match &compute.op {
            AddAddress | MulAddress => {
                let mut operands = operands.into_iter();
                let a = operands.next().unwrap().address()?;
                let b = operands.next().unwrap().address()?;
                Ok(Eval::Address(
                    if matches!(compute.op, AddAddress) {
                        a.checked_add(b)
                    } else {
                        a.checked_mul(b)
                    }
                    .ok_or_else(|| eyre!("Circom address computation overflowed"))?,
                ))
            }
            ToAddress => {
                let (nodes, _) = operands.into_iter().next().unwrap().values()?;
                let value = self.graph.constant_value(nodes[0])?;
                Ok(Eval::Address(
                    usize::try_from(value)
                        .map_err(|_| eyre!("Circom address does not fit usize"))?,
                ))
            }
            Eq(size) => {
                let mut operands = operands.into_iter();
                let (left, left_component) = operands.next().unwrap().values()?;
                let (right, right_component) = operands.next().unwrap().values()?;
                let component = left_component.or(right_component);
                let size = self.resolve_size_option(size, component)?;
                if size == 0 || left.len() < size || right.len() < size {
                    bail!("invalid multi-value equality in Circom IR");
                }
                let mut result = self.graph.op(Operation::Eq, left[0], right[0]);
                for index in 1..size {
                    let equal = self.graph.op(Operation::Eq, left[index], right[index]);
                    result = self.graph.op(Operation::Land, result, equal);
                }
                Ok(Eval::Values {
                    nodes: vec![result],
                    component: None,
                })
            }
            operation => {
                let operation = operation_from_circom(operation)?;
                let mut operands = operands.into_iter();
                let (left, _) = operands.next().unwrap().values()?;
                let a = *left
                    .first()
                    .ok_or_else(|| eyre!("Circom operation has an empty left operand"))?;
                let b = if let Some(right) = operands.next() {
                    *right
                        .values()?
                        .0
                        .first()
                        .ok_or_else(|| eyre!("Circom operation has an empty right operand"))?
                } else {
                    a
                };
                Ok(Eval::Values {
                    nodes: vec![self.graph.op(operation, a, b)],
                    component: None,
                })
            }
        }
    }

    fn execute_store(&mut self, store: &StoreBucket, frame: &mut Frame) -> Result<()> {
        let place = self.resolve_place(&store.dest_address_type, &store.dest, frame)?;
        let destination_size = self.resolve_size(&store.context, place.component)?;
        let (source, source_component) = self.eval(store.src.as_ref(), frame)?.values()?;
        let source_size_component = if let Some(component_address) = &store.src_address_type {
            Some(self.resolve_subcomponent(frame, component_address.as_ref())?)
        } else {
            source_component
        };
        let source_size = self.resolve_size(&store.src_context, source_size_component)?;
        let size = destination_size.min(source_size);
        if source.len() < size {
            bail!("Circom store source is shorter than its declared size");
        }
        self.write_place(&place, &source[..size], frame)?;
        self.update_subcomponent_after_write(&store.dest_address_type, place.component, size)?;
        Ok(())
    }

    fn execute_call(&mut self, call: &CallBucket, frame: &mut Frame) -> Result<Option<Eval>> {
        let mut arguments = Vec::new();
        for (argument, context) in call.arguments.iter().zip(&call.argument_types) {
            let (values, component) = self.eval(argument.as_ref(), frame)?.values()?;
            let size = self.resolve_size(context, component)?;
            if values.len() < size {
                bail!("Circom call argument is shorter than its declared size");
            }
            arguments.extend_from_slice(&values[..size]);
        }

        let circuit = self.circuit;
        let function = circuit
            .functions
            .iter()
            .find(|function| function.header == call.symbol)
            .ok_or_else(|| eyre!("Circom function {} was not found", call.symbol))?;
        let is_black_box = function.name.starts_with("bbf");

        match &call.return_info {
            ReturnType::Intermediate { .. } => {
                let node = if is_black_box {
                    self.graph.black_box(call.symbol.clone(), arguments)
                } else {
                    let values = self.execute_function_or_runtime(
                        &call.symbol,
                        arguments,
                        call.arena_size,
                        frame.component,
                        1,
                    )?;
                    *values
                        .first()
                        .ok_or_else(|| eyre!("Circom function {} returned no value", call.symbol))?
                };
                Ok(Some(Eval::Values {
                    nodes: vec![node],
                    component: None,
                }))
            }
            ReturnType::Final(data) => {
                let place = self.resolve_place(&data.dest_address_type, &data.dest, frame)?;
                let size = self.resolve_size(&data.context, place.component)?;
                let values = if is_black_box {
                    if size != 1 {
                        bail!("black-box Circom functions may only return one value");
                    }
                    vec![self.graph.black_box(call.symbol.clone(), arguments)]
                } else {
                    self.execute_function_or_runtime(
                        &call.symbol,
                        arguments,
                        call.arena_size,
                        frame.component,
                        size,
                    )?
                };
                if values.len() < size {
                    bail!("Circom function {} returned too few values", call.symbol);
                }
                self.write_place(&place, &values[..size], frame)?;
                self.update_subcomponent_after_write(
                    &data.dest_address_type,
                    place.component,
                    size,
                )?;
                Ok(None)
            }
        }
    }

    fn create_components(&mut self, create: &CreateCmpBucket, frame: &mut Frame) -> Result<()> {
        let subcomponent_start = self.eval(create.sub_cmp_id.as_ref(), frame)?.address()?;
        let parent_signal_start = self.component(frame.component)?.signal_start;
        for (created_index, (position, _)) in create.defined_positions.iter().enumerate() {
            let component_id = frame.component
                + create.component_offset
                + 1
                + created_index * create.component_offset_jump;
            let signal_start = parent_signal_start
                + create.signal_offset
                + created_index * create.signal_offset_jump;
            let template = self.circuit.get_template(create.template_id);
            let component = Component {
                template_id: create.template_id,
                signal_start,
                input_counter: template.number_of_inputs,
                subcomponents: vec![None; template.number_of_components],
                ran: false,
            };
            let slot = subcomponent_start + position;
            let parent = self.component_mut(frame.component)?;
            if slot >= parent.subcomponents.len() {
                bail!("Circom subcomponent slot {slot} is out of bounds");
            }
            parent.subcomponents[slot] = Some(component_id);
            let target = self
                .components
                .get_mut(component_id)
                .ok_or_else(|| eyre!("Circom component {component_id} is out of bounds"))?;
            if target.is_some() {
                bail!("Circom component {component_id} was created more than once");
            }
            *target = Some(component);
            if template.number_of_inputs == 0 {
                self.run_template(component_id)?;
            }
        }
        Ok(())
    }

    fn resolve_place(
        &mut self,
        address_type: &AddressType,
        location: &LocationRule,
        frame: &mut Frame,
    ) -> Result<Place> {
        let component = match address_type {
            AddressType::SubcmpSignal { cmp_address, .. } => {
                Some(self.resolve_subcomponent(frame, cmp_address.as_ref())?)
            }
            AddressType::Variable | AddressType::Signal => None,
        };
        let local_offset = match location {
            LocationRule::Indexed { location, .. } => {
                self.eval(location.as_ref(), frame)?.address()?
            }
            LocationRule::Mapped {
                signal_code,
                indexes,
            } => self.resolve_mapped_offset(
                component.ok_or_else(|| eyre!("mapped Circom access is not a subcomponent"))?,
                *signal_code,
                indexes,
                frame,
            )?,
        };

        match address_type {
            AddressType::Variable => Ok(Place {
                memory: Memory::Variables,
                offset: local_offset,
                component: None,
            }),
            AddressType::Signal => Ok(Place {
                memory: Memory::Signals,
                offset: self.component(frame.component)?.signal_start + local_offset,
                component: None,
            }),
            AddressType::SubcmpSignal { .. } => {
                let component = component.unwrap();
                Ok(Place {
                    memory: Memory::Signals,
                    offset: self.component(component)?.signal_start + local_offset,
                    component: Some(component),
                })
            }
        }
    }

    fn resolve_mapped_offset(
        &mut self,
        component: usize,
        signal_code: usize,
        indexes: &[AccessType],
        frame: &mut Frame,
    ) -> Result<usize> {
        #[derive(Clone)]
        struct Definition {
            offset: usize,
            lengths: Vec<usize>,
            size: usize,
            bus_id: Option<usize>,
        }

        let template_id = self.component(component)?.template_id;
        let io_map = self
            .circuit
            .c_producer
            .io_map
            .get(&template_id)
            .ok_or_else(|| eyre!("Circom IO map is missing template {template_id}"))?;
        let io = io_map
            .get(signal_code)
            .ok_or_else(|| eyre!("Circom IO signal {signal_code} is missing"))?;
        let mut definition = Definition {
            offset: io.offset,
            lengths: io.lengths.clone(),
            size: io.size,
            bus_id: io.bus_id,
        };
        let mut offset = definition.offset;

        for (access_index, access) in indexes.iter().enumerate() {
            match access {
                AccessType::Indexed(info) => {
                    if info.indexes.is_empty() || info.indexes.len() > info.symbol_dim {
                        bail!("invalid indexed Circom IO access");
                    }
                    let mut index = self.eval(info.indexes[0].as_ref(), frame)?.address()?;
                    for (dimension, expression) in info.indexes.iter().enumerate().skip(1) {
                        let next = self.eval(expression.as_ref(), frame)?.address()?;
                        index = index
                            .checked_mul(definition.lengths[dimension - 1])
                            .and_then(|value| value.checked_add(next))
                            .ok_or_else(|| eyre!("Circom mapped index overflowed"))?;
                    }
                    if info.indexes.len() < info.symbol_dim {
                        if access_index + 1 != indexes.len() {
                            bail!("partial Circom array access must be last");
                        }
                        for dimension in info.indexes.len()..info.symbol_dim {
                            index = index
                                .checked_mul(definition.lengths[dimension - 1])
                                .ok_or_else(|| eyre!("Circom mapped index overflowed"))?;
                        }
                    }
                    offset = offset
                        .checked_add(
                            index
                                .checked_mul(definition.size)
                                .ok_or_else(|| eyre!("Circom mapped offset overflowed"))?,
                        )
                        .ok_or_else(|| eyre!("Circom mapped offset overflowed"))?;
                }
                AccessType::Qualified(field) => {
                    let bus_id = definition
                        .bus_id
                        .ok_or_else(|| eyre!("qualified Circom access is not a bus"))?;
                    let field = self.circuit.c_producer.busid_field_info[bus_id]
                        .get(*field)
                        .ok_or_else(|| eyre!("Circom bus field is missing"))?;
                    definition = Definition {
                        offset: field.offset,
                        lengths: field.dimensions.clone(),
                        size: field.size,
                        bus_id: field.bus_id,
                    };
                    offset = offset
                        .checked_add(definition.offset)
                        .ok_or_else(|| eyre!("Circom mapped offset overflowed"))?;
                }
            }
        }
        Ok(offset)
    }

    fn read_place(&self, place: &Place, size: usize, frame: &Frame) -> Result<Vec<usize>> {
        let memory = match place.memory {
            Memory::Variables => &frame.variables,
            Memory::Signals => &self.signals,
        };
        let end = place
            .offset
            .checked_add(size)
            .ok_or_else(|| eyre!("Circom memory read overflowed"))?;
        let values = memory
            .get(place.offset..end)
            .ok_or_else(|| eyre!("Circom memory read is out of bounds"))?;
        values
            .iter()
            .enumerate()
            .map(|(index, value)| {
                value.ok_or_else(|| {
                    eyre!(
                        "Circom read uninitialized memory at {}",
                        place.offset + index
                    )
                })
            })
            .collect()
    }

    fn write_place(&mut self, place: &Place, values: &[usize], frame: &mut Frame) -> Result<()> {
        if matches!(place.memory, Memory::Signals) {
            for offset in 0..values.len() {
                let index = place.offset + offset;
                for undo in &mut self.signal_undos {
                    undo.entry(index).or_insert(self.signals[index]);
                }
            }
        }
        let memory = match place.memory {
            Memory::Variables => &mut frame.variables,
            Memory::Signals => &mut self.signals,
        };
        let end = place
            .offset
            .checked_add(values.len())
            .ok_or_else(|| eyre!("Circom memory write overflowed"))?;
        let destination = memory
            .get_mut(place.offset..end)
            .ok_or_else(|| eyre!("Circom memory write is out of bounds"))?;
        for (destination, value) in destination.iter_mut().zip(values) {
            *destination = Some(*value);
        }
        Ok(())
    }

    fn resolve_subcomponent(&mut self, frame: &mut Frame, address: &Instruction) -> Result<usize> {
        let slot = self.eval(address, frame)?.address()?;
        self.component(frame.component)?
            .subcomponents
            .get(slot)
            .and_then(|component| *component)
            .ok_or_else(|| eyre!("Circom subcomponent slot {slot} is not initialized"))
    }

    fn resolve_size(&self, context: &InstrContext, component: Option<usize>) -> Result<usize> {
        self.resolve_size_option(&context.size, component)
    }

    fn resolve_size_option(&self, size: &SizeOption, component: Option<usize>) -> Result<usize> {
        match size {
            SizeOption::Single(size) => Ok(*size),
            SizeOption::Multiple(sizes) => {
                let component = component
                    .ok_or_else(|| eyre!("Circom value size depends on a missing component"))?;
                let template_id = self.component(component)?.template_id;
                sizes
                    .iter()
                    .find_map(|(candidate, size)| (*candidate == template_id).then_some(*size))
                    .ok_or_else(|| eyre!("Circom value has no size for template {template_id}"))
            }
        }
    }

    fn compile_runtime_function(&mut self, symbol: &str, component: usize) -> Result<usize> {
        let template_id = self.component(component)?.template_id;
        let key = (symbol.to_owned(), template_id);
        if let Some(&function) = self.runtime_function_ids.get(&key) {
            return Ok(function);
        }
        let function = self
            .circuit
            .functions
            .iter()
            .find(|function| function.header == symbol)
            .ok_or_else(|| eyre!("Circom function {symbol} was not found"))?;
        let name = function.header.clone();
        let variable_count = function.max_number_of_vars;
        let body = function.body.clone();

        let id = self.runtime_functions.len();
        self.runtime_functions.push(None);
        self.runtime_function_ids.insert(key, id);
        let body = self.translate_runtime_list(&body, component)?;
        self.runtime_functions[id] = Some(RuntimeFunction {
            name,
            variable_count,
            body,
        });
        Ok(id)
    }

    fn translate_runtime_list(
        &mut self,
        body: &InstructionList,
        component: usize,
    ) -> Result<Vec<RuntimeStatement>> {
        let mut translated = Vec::new();
        for instruction in body {
            match instruction.as_ref() {
                Instruction::Store(store) => {
                    if !matches!(store.dest_address_type, AddressType::Variable)
                        || store.src_address_type.is_some()
                    {
                        bail!("runtime Circom functions may only access local variables")
                    }
                    let destination_size = self.resolve_size(&store.context, Some(component))?;
                    let source_size = self.resolve_size(&store.src_context, Some(component))?;
                    translated.push(RuntimeStatement::Store {
                        offset: self.translate_runtime_location(&store.dest, component)?,
                        size: destination_size.min(source_size),
                        value: self.translate_runtime_expression(store.src.as_ref(), component)?,
                    });
                }
                Instruction::Call(call) => match &call.return_info {
                    ReturnType::Intermediate { .. } => translated.push(RuntimeStatement::Call(
                        self.translate_runtime_call(call, component, 1)?,
                    )),
                    ReturnType::Final(data) => {
                        if !matches!(data.dest_address_type, AddressType::Variable) {
                            bail!("runtime Circom functions may only store local call results")
                        }
                        let size = self.resolve_size(&data.context, Some(component))?;
                        translated.push(RuntimeStatement::Store {
                            offset: self.translate_runtime_location(&data.dest, component)?,
                            size,
                            value: self.translate_runtime_call(call, component, size)?,
                        });
                    }
                },
                Instruction::Branch(branch) => translated.push(RuntimeStatement::Branch {
                    condition: self
                        .translate_runtime_expression(branch.cond.as_ref(), component)?,
                    if_branch: self.translate_runtime_list(&branch.if_branch, component)?,
                    else_branch: self.translate_runtime_list(&branch.else_branch, component)?,
                }),
                Instruction::Loop(loop_bucket) => translated.push(RuntimeStatement::Loop {
                    condition: self.translate_runtime_expression(
                        loop_bucket.continue_condition.as_ref(),
                        component,
                    )?,
                    body: self.translate_runtime_list(&loop_bucket.body, component)?,
                }),
                Instruction::Return(return_bucket) => translated.push(RuntimeStatement::Return {
                    value: self
                        .translate_runtime_expression(return_bucket.value.as_ref(), component)?,
                    size: return_bucket.with_size,
                }),
                Instruction::Value(_) | Instruction::Load(_) | Instruction::Compute(_) => {
                    translated.push(RuntimeStatement::Call(
                        self.translate_runtime_expression(instruction.as_ref(), component)?,
                    ));
                }
                Instruction::Assert(_) | Instruction::Log(_) => {}
                Instruction::CreateCmp(_) => {
                    bail!("runtime Circom functions cannot create components")
                }
            }
        }
        Ok(translated)
    }

    fn translate_runtime_expression(
        &mut self,
        instruction: &Instruction,
        component: usize,
    ) -> Result<RuntimeExpression> {
        Ok(match instruction {
            Instruction::Value(value) => match value.parse_as {
                ValueType::U32 => RuntimeExpression::Address(value.value),
                ValueType::BigInt => {
                    RuntimeExpression::Field(self.graph.values[self.constants[value.value]])
                }
            },
            Instruction::Load(load) => {
                if !matches!(load.address_type, AddressType::Variable) {
                    bail!("runtime Circom functions may only load local variables")
                }
                RuntimeExpression::Load {
                    offset: Box::new(self.translate_runtime_location(&load.src, component)?),
                    size: self.resolve_size(&load.context, Some(component))?,
                }
            }
            Instruction::Compute(compute) => {
                let operation = match &compute.op {
                    OperatorType::AddAddress => RuntimeOperation::AddAddress,
                    OperatorType::MulAddress => RuntimeOperation::MulAddress,
                    OperatorType::ToAddress => RuntimeOperation::ToAddress,
                    OperatorType::Eq(size) => {
                        RuntimeOperation::Equal(self.resolve_size_option(size, Some(component))?)
                    }
                    operation => RuntimeOperation::Field(operation_from_circom(operation)?),
                };
                RuntimeExpression::Compute {
                    operation,
                    operands: compute
                        .stack
                        .iter()
                        .map(|operand| {
                            self.translate_runtime_expression(operand.as_ref(), component)
                        })
                        .collect::<Result<Vec<_>>>()?,
                }
            }
            Instruction::Call(call) => {
                let ReturnType::Intermediate { .. } = call.return_info else {
                    bail!("a final Circom call cannot be a runtime expression")
                };
                self.translate_runtime_call(call, component, 1)?
            }
            _ => bail!("Circom statement cannot be a runtime expression"),
        })
    }

    fn translate_runtime_call(
        &mut self,
        call: &CallBucket,
        component: usize,
        result_size: usize,
    ) -> Result<RuntimeExpression> {
        let function = self.compile_runtime_function(&call.symbol, component)?;
        let mut arguments = Vec::with_capacity(call.arguments.len());
        for (argument, context) in call.arguments.iter().zip(&call.argument_types) {
            arguments.push((
                self.translate_runtime_expression(argument.as_ref(), component)?,
                self.resolve_size(context, Some(component))?,
            ));
        }
        Ok(RuntimeExpression::Call {
            function,
            arena_size: call.arena_size,
            result_size,
            arguments,
        })
    }

    fn translate_runtime_location(
        &mut self,
        location: &LocationRule,
        component: usize,
    ) -> Result<RuntimeExpression> {
        match location {
            LocationRule::Indexed { location, .. } => {
                self.translate_runtime_expression(location.as_ref(), component)
            }
            LocationRule::Mapped { .. } => {
                bail!("runtime Circom functions cannot use mapped component locations")
            }
        }
    }

    fn execute_dynamic_template_branch(
        &mut self,
        condition: usize,
        if_branch: &InstructionList,
        else_branch: &InstructionList,
        frame: &mut Frame,
    ) -> Result<()> {
        if !branch_has_local_effects(if_branch) || !branch_has_local_effects(else_branch) {
            bail!("input-dependent Circom template branch has component side effects")
        }

        let base_variables = frame.variables.clone();
        let (if_flow, if_variables, if_signals) =
            self.execute_template_branch_side(if_branch, frame)?;
        frame.variables.clone_from(&base_variables);
        let (else_flow, else_variables, else_signals) =
            self.execute_template_branch_side(else_branch, frame)?;
        if !matches!((if_flow, else_flow), (Flow::Continue, Flow::Continue)) {
            bail!("input-dependent Circom template branch cannot return a value")
        }

        for index in 0..frame.variables.len() {
            frame.variables[index] = self.merge_optional_nodes(
                condition,
                if_variables[index],
                else_variables[index],
                "variable",
                index,
            )?;
        }

        let signal_indexes = if_signals
            .keys()
            .chain(else_signals.keys())
            .copied()
            .collect::<HashSet<_>>();
        for index in signal_indexes {
            let base = self.signals[index];
            let if_value = if_signals.get(&index).copied().unwrap_or(base);
            let else_value = else_signals.get(&index).copied().unwrap_or(base);
            let merged =
                self.merge_optional_nodes(condition, if_value, else_value, "signal", index)?;
            self.set_signal(index, merged);
        }
        Ok(())
    }

    fn execute_template_branch_side(
        &mut self,
        body: &InstructionList,
        frame: &mut Frame,
    ) -> Result<TemplateBranchSide> {
        let graph_start = self.graph.nodes.len();
        self.signal_undos.push(HashMap::new());
        let result = self.execute_list(body, frame);
        for node in &mut self.graph.nodes[graph_start..] {
            if let Node::Op(operation, _, _) = node {
                if *operation == Operation::Div {
                    *operation = Operation::SafeDiv;
                }
            }
        }
        let undo = self.signal_undos.pop().unwrap();
        let values = undo
            .keys()
            .map(|&index| (index, self.signals[index]))
            .collect::<HashMap<_, _>>();
        for (&index, &original) in &undo {
            self.signals[index] = original;
        }
        let flow = result?;
        Ok((flow, frame.variables.clone(), values))
    }

    fn merge_optional_nodes(
        &mut self,
        condition: usize,
        if_value: Option<usize>,
        else_value: Option<usize>,
        kind: &str,
        index: usize,
    ) -> Result<Option<usize>> {
        match (if_value, else_value) {
            (None, None) => Ok(None),
            (Some(if_value), Some(else_value)) if if_value == else_value => Ok(Some(if_value)),
            (Some(if_value), Some(else_value)) => {
                let zero = self.graph.constant(U256::ZERO);
                let condition = self.graph.op(Operation::Neq, condition, zero);
                let difference = self.graph.op(Operation::Sub, if_value, else_value);
                let selected = self.graph.op(Operation::Mul, condition, difference);
                Ok(Some(self.graph.op(Operation::Add, else_value, selected)))
            }
            _ => bail!("input-dependent Circom branch initializes {kind} {index} on only one path"),
        }
    }

    fn set_signal(&mut self, index: usize, value: Option<usize>) {
        for undo in &mut self.signal_undos {
            undo.entry(index).or_insert(self.signals[index]);
        }
        self.signals[index] = value;
    }

    fn eval_condition(&mut self, instruction: &Instruction, frame: &mut Frame) -> Result<bool> {
        let node = self.eval_condition_node(instruction, frame)?;
        Ok(self.graph.constant_value(node)? != U256::ZERO)
    }

    fn eval_condition_node(
        &mut self,
        instruction: &Instruction,
        frame: &mut Frame,
    ) -> Result<usize> {
        let (nodes, _) = self.eval(instruction, frame)?.values()?;
        nodes
            .first()
            .copied()
            .ok_or_else(|| eyre!("Circom condition is empty"))
    }

    fn update_subcomponent_after_write(
        &mut self,
        address_type: &AddressType,
        component: Option<usize>,
        size: usize,
    ) -> Result<()> {
        let AddressType::SubcmpSignal {
            input_information, ..
        } = address_type
        else {
            return Ok(());
        };
        let InputInformation::Input { status } = input_information else {
            return Ok(());
        };
        let component = component.unwrap();
        let state = self.component_mut(component)?;
        state.input_counter = state
            .input_counter
            .checked_sub(size)
            .ok_or_else(|| eyre!("too many inputs were written to Circom component {component}"))?;
        let ready = state.input_counter == 0;
        match status {
            StatusInput::Last if !ready => {
                bail!("Circom marked an input write as last before all inputs were assigned")
            }
            StatusInput::NoLast if ready => {
                bail!("Circom marked an input write as non-final after all inputs were assigned")
            }
            StatusInput::Last | StatusInput::NoLast | StatusInput::Unknown => {}
        }
        if ready {
            self.run_template(component)?;
        }
        Ok(())
    }

    fn component(&self, id: usize) -> Result<&Component> {
        self.components
            .get(id)
            .and_then(Option::as_ref)
            .ok_or_else(|| eyre!("Circom component {id} is not initialized"))
    }

    fn component_mut(&mut self, id: usize) -> Result<&mut Component> {
        self.components
            .get_mut(id)
            .and_then(Option::as_mut)
            .ok_or_else(|| eyre!("Circom component {id} is not initialized"))
    }
}

fn branch_has_local_effects(body: &InstructionList) -> bool {
    body.iter().all(|instruction| match instruction.as_ref() {
        Instruction::Store(store) => matches!(
            store.dest_address_type,
            AddressType::Variable | AddressType::Signal
        ),
        Instruction::Call(call) => match &call.return_info {
            ReturnType::Intermediate { .. } => true,
            ReturnType::Final(data) => matches!(
                data.dest_address_type,
                AddressType::Variable | AddressType::Signal
            ),
        },
        Instruction::Branch(branch) => {
            branch_has_local_effects(&branch.if_branch)
                && branch_has_local_effects(&branch.else_branch)
        }
        Instruction::Loop(_) | Instruction::CreateCmp(_) => false,
        Instruction::Value(_)
        | Instruction::Load(_)
        | Instruction::Compute(_)
        | Instruction::Return(_)
        | Instruction::Assert(_)
        | Instruction::Log(_) => true,
    })
}

fn operation_from_circom(operation: &OperatorType) -> Result<Operation> {
    use OperatorType::*;
    Ok(match operation {
        Mul => Operation::Mul,
        Div => Operation::Div,
        Add => Operation::Add,
        Sub => Operation::Sub,
        Pow => Operation::Pow,
        IntDiv => Operation::IDiv,
        Mod => Operation::Mod,
        ShiftL => Operation::Shl,
        ShiftR => Operation::Shr,
        LesserEq => Operation::Leq,
        GreaterEq => Operation::Geq,
        Lesser => Operation::Lt,
        Greater => Operation::Gt,
        NotEq => Operation::Neq,
        BoolOr => Operation::Lor,
        BoolAnd => Operation::Land,
        BitOr => Operation::Bor,
        BitAnd => Operation::Band,
        BitXor => Operation::Bxor,
        PrefixSub => Operation::Neg,
        BoolNot => Operation::Lnot,
        Complement => Operation::Bnot,
        Eq(_) | ToAddress | MulAddress | AddAddress => {
            bail!("Circom operator was routed to the wrong evaluator")
        }
    })
}

fn parse_field_constant(value: &str) -> Result<U256> {
    if let Some(value) = value.strip_prefix('-') {
        let magnitude = value
            .parse::<U256>()
            .wrap_err_with(|| format!("invalid Circom field constant -{value}"))?
            % M;
        Ok((M - magnitude) % M)
    } else {
        Ok(value
            .parse::<U256>()
            .wrap_err_with(|| format!("invalid Circom field constant {value}"))?
            % M)
    }
}

fn compile_circuit(
    circuit_path: &Path,
    library_paths: &[PathBuf],
    use_o1: bool,
) -> Result<Circuit> {
    let prime = M
        .to_string()
        .parse::<circom_compiler::num_bigint::BigInt>()
        .map_err(|error| eyre!("failed to construct Circom prime: {error}"))?;
    let (mut program, _) = circom_parser::run_parser(
        circuit_path.to_string_lossy().into_owned(),
        CIRCOM_VERSION,
        library_paths.to_vec(),
        &prime,
        false,
    )
    .map_err(|(_, reports)| eyre!("Circom parsing failed with {} report(s)", reports.len()))?;
    circom_type_analysis::check_types::check_types(&mut program).map_err(|reports| {
        eyre!(
            "Circom type analysis failed with {} report(s)",
            reports.len()
        )
    })?;

    let (_, vcp) = build_circuit(
        program,
        BuildConfig {
            no_rounds: if use_o1 { 0 } else { usize::MAX },
            flag_json_sub: false,
            json_substitutions: String::new(),
            flag_s: use_o1,
            flag_f: false,
            flag_p: false,
            flag_verbose: false,
            flag_old_heuristics: false,
            inspect_constraints: false,
            prime: "bn128".to_owned(),
        },
    )
    .map_err(|()| eyre!("Circom constraint generation failed"))?;

    compiler_interface::run_compiler(
        vcp,
        Config {
            debug_output: false,
            produce_input_log: false,
            wat_flag: false,
            no_asm_flag: true,
            constraint_assert_disabled_flag: false,
        },
        CIRCOM_VERSION,
    )
    .map_err(|()| eyre!("Circom IR generation failed"))
}

fn fnv1a(value: &str) -> u64 {
    let mut hash = 0xCBF29CE484222325_u64;
    for byte in value.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001B3);
    }
    hash
}

/// Compile a Circom circuit and return its optimized, serialized witness graph.
pub fn generate_witness_graph_from_file(
    circuit_path: impl AsRef<Path>,
    library_paths: &[PathBuf],
) -> Result<Vec<u8>> {
    generate_witness_graph_from_file_with_optimization(circuit_path, library_paths, false)
}

/// Compile a Circom circuit using either its O1 or O2 witness-to-signal mapping.
pub fn generate_witness_graph_from_file_with_optimization(
    circuit_path: impl AsRef<Path>,
    library_paths: &[PathBuf],
    use_o1: bool,
) -> Result<Vec<u8>> {
    let circuit_path = circuit_path.as_ref();
    let circuit = compile_circuit(circuit_path, library_paths, use_o1)?;
    let input_map = circuit
        .c_producer
        .main_input_list
        .iter()
        .map(|input| HashSignalInfo {
            hash: fnv1a(&input.name),
            signalid: input.start as u64,
            signalsize: input.size as u64,
        })
        .collect::<Vec<_>>();

    let started = std::time::Instant::now();
    let (mut nodes, mut signals, runtime_functions) = Interpreter::new(&circuit)?.build()?;
    eprintln!("Symbolic execution took: {:?}", started.elapsed());
    eprintln!("Graph with {} nodes", nodes.len());
    graph::optimize(&mut nodes, &mut signals);

    let bytes = serialize_graph_with_runtime(nodes, signals, input_map, runtime_functions)?;
    eprintln!("Graph size: {} bytes", bytes.len());
    Ok(bytes)
}

/// Compile the circuit selected through `CIRCOM_WITNESS` and return its serialized witness graph.
pub fn generate_witness_graph() -> Result<Vec<u8>> {
    let circuit_path = env::var_os("CIRCOM_WITNESS")
        .or_else(|| env::var_os("WITNESS_CPP"))
        .map(PathBuf::from)
        .ok_or_else(|| eyre!("CIRCOM_WITNESS must point to the Circom circuit to compile"))?;
    let library_paths = env::var_os("CIRCOM_LIBRARY_PATH")
        .map(PathBuf::from)
        .into_iter()
        .collect::<Vec<_>>();
    let use_o1 = env::var_os("CIRCOM_OPTIMIZATION").is_some_and(|value| value == "O1");
    generate_witness_graph_from_file_with_optimization(&circuit_path, &library_paths, use_o1)
}

/// Compile the selected circuit and write its optimized graph to `graph.bin`.
pub fn build_witness() -> Result<()> {
    std::fs::write("graph.bin", generate_witness_graph()?)?;
    Ok(())
}
