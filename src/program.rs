use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    ops::Range,
    sync::OnceLock,
};

use ark_bn254::Fr;
use ark_ff::Field;
use eyre::{bail, eyre, Context as _};
use ruint::aliases::U256;
use serde::{Deserialize, Serialize};

use crate::{
    custom::{NativeRuntimeFunction, NativeSubgraphFunction, ResolvedNativeSubgraph},
    graph::{Node, Operation},
    profile::{
        ProfileCollector, ProfileFrame, SourceNodeRange, StructuralHotspot, StructuralOccurrence,
    },
    runtime::RuntimeFunction,
    BlackBoxFunction, M,
};

/// Compact executable form of an optimized witness graph.
///
/// Instructions address values rather than instructions because `Pow5` materializes the useful
/// intermediate powers as well as the final result. Constants and linear-combination coefficients
/// share one pool, which is important for both the in-memory and serialized representation.
#[derive(Debug, Clone)]
pub(crate) struct Program {
    coefficients: Vec<Fr>,
    instructions: Vec<Instruction>,
    linear3: Vec<[(u32, u32); 3]>,
    linear4: Vec<[(u32, u32); 4]>,
    black_boxes: Vec<BlackBoxInstruction>,
    native_subgraphs: Vec<NativeInstruction>,
    runtime_functions: Vec<RuntimeFunction>,
    native_runtime_functions: Vec<NativeRuntimeFunction>,
    runtime_calls: Vec<RuntimeCallInstruction>,
    runtime_call_count: usize,
    outputs: Vec<usize>,
    division_batches: Vec<Range<usize>>,
    value_count: usize,
    input_count: usize,
    source_map: OnceLock<ProgramSourceMap>,
}

#[derive(Debug, Clone)]
struct ProgramSourceMap {
    /// Public [`Graph::nodes`](crate::Graph::nodes) IDs represented by each compact instruction.
    instruction_sources: Vec<Vec<usize>>,
    /// Public node IDs read by each instruction but represented by another instruction or pool.
    instruction_boundary_sources: Vec<Vec<usize>>,
    /// Public node ID that materializes each compact value.
    value_sources: Vec<usize>,
    node_count: usize,
}

#[derive(Default)]
pub(crate) struct EvaluationWorkspace {
    values: Vec<Fr>,
    inverses: Vec<Fr>,
    inversion_scratch: Vec<Fr>,
    black_box_parameters: Vec<Fr>,
    native_inputs: Vec<Fr>,
    native_outputs: Vec<Fr>,
    runtime_parameters: Vec<Fr>,
    runtime_results: Vec<Vec<Fr>>,
    runtime_ready: Vec<bool>,
    outputs: Vec<U256>,
}

impl EvaluationWorkspace {
    pub(crate) fn outputs(&self) -> &[U256] {
        &self.outputs
    }
}

pub(crate) struct BoundBlackBoxes {
    functions: Vec<BlackBoxFunction>,
}

#[derive(Debug, Clone)]
enum Instruction {
    Input(usize),
    Constant(u32),
    Mul(u32, u32),
    Add(u32, u32),
    Sub(u32, u32),
    Op(Operation, u32, u32),
    Square(u32),
    /// Produces, in order, `x^2`, `x^4`, and `x^5`.
    Pow5(u32),
    Linear3(u32),
    Linear4(u32),
    BlackBox(u32),
    Native(u32),
    RuntimeCall(u32),
}

#[derive(Debug, Clone)]
struct BlackBoxInstruction {
    name: String,
    parameters: Vec<u32>,
}

#[derive(Clone)]
struct NativeInstruction {
    name: String,
    inputs: Vec<u32>,
    output_count: usize,
    function: NativeSubgraphFunction,
}

impl std::fmt::Debug for NativeInstruction {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeInstruction")
            .field("name", &self.name)
            .field("inputs", &self.inputs)
            .field("output_count", &self.output_count)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeCallInstruction {
    function: usize,
    call: usize,
    output: usize,
    output_count: usize,
    arena_size: usize,
    argument_sizes: Vec<usize>,
    parameters: Vec<u32>,
}

/// Stable on-disk representation. References are converted to backward deltas by `encode` and
/// restored to absolute value IDs by `decode`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct EncodedProgram {
    coefficients: Vec<[u8; 32]>,
    instructions: Vec<EncodedInstruction>,
    output_deltas: Vec<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum EncodedInstruction {
    Input(usize),
    Constant(usize),
    Mul(usize, usize),
    Add(usize, usize),
    Sub(usize, usize),
    Op(Operation, usize, usize),
    Square(usize),
    Pow5(usize),
    Linear3([(usize, usize); 3]),
    Linear4([(usize, usize); 4]),
    BlackBox(String, Vec<usize>),
    RuntimeCall {
        function: usize,
        call: usize,
        output: usize,
        output_count: usize,
        arena_size: usize,
        argument_sizes: Vec<usize>,
        parameters: Vec<usize>,
    },
}

#[derive(Default)]
struct LinearSpec {
    terms: Vec<(usize, Fr)>,
    skip: Vec<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct StructuralShape {
    fingerprint: [u8; 16],
    compact_instructions: usize,
    graph_nodes: usize,
    boundary_values: usize,
}

#[derive(Clone, Copy)]
struct StableShapeHasher {
    left: u64,
    right: u64,
}

impl StableShapeHasher {
    fn new() -> Self {
        Self {
            left: 0xcbf29ce484222325,
            right: 0x84222325cbf29ce4,
        }
    }

    fn write(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.left ^= u64::from(byte);
            self.left = self.left.wrapping_mul(0x100000001b3);
            self.right ^= u64::from(byte);
            self.right = self.right.wrapping_mul(0x100000001b3);
            self.right ^= self.right.rotate_left(23);
        }
    }

    fn write_usize(&mut self, value: usize) {
        self.write(&(value as u64).to_le_bytes());
    }

    fn finish(self) -> [u8; 16] {
        let mut output = [0_u8; 16];
        output[..8].copy_from_slice(&self.left.to_le_bytes());
        output[8..].copy_from_slice(&self.right.to_le_bytes());
        output
    }
}

fn strip_suffix_number(name: &str) -> String {
    if let Some(position) = name.rfind('_') {
        let suffix = &name[position + 1..];
        if suffix.bytes().all(|byte| byte.is_ascii_digit()) {
            return name[..position].to_owned();
        }
    }
    name.to_owned()
}

fn check_reference(node: usize, reference: usize) -> eyre::Result<()> {
    if reference >= node {
        bail!("graph node {node} references non-earlier node {reference}");
    }
    Ok(())
}

fn validate_graph(nodes: &[Node], outputs: &[usize]) -> eyre::Result<()> {
    for (index, node) in nodes.iter().enumerate() {
        match node {
            Node::Op(_, left, right) => {
                check_reference(index, *left)?;
                check_reference(index, *right)?;
            }
            Node::BBF(_, parameters) => {
                for &parameter in parameters {
                    check_reference(index, parameter)?;
                }
            }
            Node::RuntimeCall { parameters, .. } => {
                for &parameter in parameters {
                    check_reference(index, parameter)?;
                }
            }
            Node::Input(_) | Node::Constant(_) | Node::MontConstant(_) => {}
        }
    }
    for &output in outputs {
        if output >= nodes.len() {
            bail!("graph output node {output} is out of bounds");
        }
    }
    Ok(())
}

fn add_linear_terms(
    index: usize,
    sign: Fr,
    nodes: &[Node],
    uses: &[usize],
    outputs: &HashSet<usize>,
    opaque: &[bool],
    spec: &mut LinearSpec,
) {
    // Large generated graphs can contain very deep single-use addition chains. Keep this traversal
    // iterative so valid legacy or fused input cannot overflow the Rust call stack during init.
    let mut pending = vec![(index, sign, true)];
    while let Some((index, sign, flatten)) = pending.pop() {
        let children = if flatten && !opaque[index] {
            match nodes[index] {
                Node::Op(Operation::Add, left, right) => Some([(left, sign), (right, sign)]),
                Node::Op(Operation::Sub, left, right) => Some([(left, sign), (right, -sign)]),
                _ => None,
            }
        } else {
            None
        };

        if let Some(children) = children {
            // Reverse push order preserves the graph's original left-to-right term order.
            for (child, child_sign) in children.into_iter().rev() {
                let inline = matches!(
                    nodes[child],
                    Node::Op(Operation::Add | Operation::Sub, _, _)
                ) && uses[child] == 1
                    && !outputs.contains(&child)
                    && !opaque[child];
                if inline {
                    spec.skip.push(child);
                }
                pending.push((child, child_sign, inline));
            }
        } else {
            add_linear_leaf(index, sign, nodes, uses, outputs, opaque, spec);
        }
    }
}

fn add_linear_leaf(
    index: usize,
    sign: Fr,
    nodes: &[Node],
    uses: &[usize],
    outputs: &HashSet<usize>,
    opaque: &[bool],
    spec: &mut LinearSpec,
) {
    if !opaque[index] && uses[index] == 1 && !outputs.contains(&index) {
        if let Node::Op(Operation::Mul, left, right) = nodes[index] {
            match (&nodes[left], &nodes[right]) {
                (Node::MontConstant(coefficient), _) => {
                    spec.skip.push(index);
                    spec.terms.push((right, sign * coefficient));
                    return;
                }
                (_, Node::MontConstant(coefficient)) => {
                    spec.skip.push(index);
                    spec.terms.push((left, sign * coefficient));
                    return;
                }
                (Node::Constant(coefficient), _) => {
                    spec.skip.push(index);
                    spec.terms
                        .push((right, sign * Fr::new((*coefficient).into())));
                    return;
                }
                (_, Node::Constant(coefficient)) => {
                    spec.skip.push(index);
                    spec.terms
                        .push((left, sign * Fr::new((*coefficient).into())));
                    return;
                }
                _ => {}
            }
        }
    }
    spec.terms.push((index, sign));
}

fn linear_specs(
    nodes: &[Node],
    outputs: &[usize],
    uses: &[usize],
    opaque: &[bool],
) -> (Vec<Option<LinearSpec>>, Vec<bool>) {
    let output_set = outputs.iter().copied().collect::<HashSet<_>>();
    let mut sole_user = vec![None; nodes.len()];
    for (index, node) in nodes.iter().enumerate() {
        match node {
            Node::Op(_, left, right) => {
                sole_user[*left] = Some(index);
                sole_user[*right] = Some(index);
            }
            Node::BBF(_, parameters) => {
                for &parameter in parameters {
                    sole_user[parameter] = Some(index);
                }
            }
            Node::RuntimeCall { parameters, .. } => {
                for &parameter in parameters {
                    sole_user[parameter] = Some(index);
                }
            }
            _ => {}
        }
    }

    let mut specs = (0..nodes.len()).map(|_| None).collect::<Vec<_>>();
    let mut skip = vec![false; nodes.len()];
    for (index, node) in nodes.iter().enumerate() {
        if opaque[index] || !matches!(node, Node::Op(Operation::Add | Operation::Sub, _, _)) {
            continue;
        }
        let is_inline_child = uses[index] == 1
            && !output_set.contains(&index)
            && !opaque[index]
            && sole_user[index].is_some_and(|user| {
                !opaque[user]
                    && matches!(nodes[user], Node::Op(Operation::Add | Operation::Sub, _, _))
            });
        if is_inline_child {
            continue;
        }

        let mut spec = LinearSpec::default();
        add_linear_terms(
            index,
            Fr::from(1_u64),
            nodes,
            uses,
            &output_set,
            opaque,
            &mut spec,
        );
        if (3..=4).contains(&spec.terms.len()) && !spec.skip.is_empty() {
            for &skipped in &spec.skip {
                skip[skipped] = true;
            }
            specs[index] = Some(spec);
        }
    }
    (specs, skip)
}

fn intern_coefficient(
    value: Fr,
    coefficients: &mut Vec<Fr>,
    indices: &mut BTreeMap<[u8; 32], usize>,
) -> usize {
    let key = fr_bytes(value);
    if let Some(&index) = indices.get(&key) {
        index
    } else {
        let index = coefficients.len();
        coefficients.push(value);
        indices.insert(key, index);
        index
    }
}

fn narrow_id(value: usize, kind: &str) -> eyre::Result<u32> {
    u32::try_from(value).map_err(|_| eyre!("{kind} {value} does not fit the compact program"))
}

/// Compiles nodes into the runtime program. `division_node_batches` refers to ranges in `nodes`
/// produced by `prepare_evaluation`; pass an empty slice for a program that is only serialized.
pub(crate) fn compile(
    nodes: &[Node],
    outputs: &[usize],
    division_node_batches: &[Range<usize>],
    runtime_functions: Vec<RuntimeFunction>,
) -> eyre::Result<Program> {
    compile_internal(
        nodes,
        outputs,
        division_node_batches,
        runtime_functions,
        &[],
        true,
    )
}

/// Compiles directly to the on-disk form without retaining process-local profiling provenance.
pub(crate) fn compile_for_serialization(
    nodes: &[Node],
    outputs: &[usize],
    runtime_functions: Vec<RuntimeFunction>,
) -> eyre::Result<Program> {
    compile_internal(nodes, outputs, &[], runtime_functions, &[], false)
}

pub(crate) fn compile_with_native(
    nodes: &[Node],
    outputs: &[usize],
    division_node_batches: &[Range<usize>],
    runtime_functions: Vec<RuntimeFunction>,
    replacements: &[ResolvedNativeSubgraph],
) -> eyre::Result<Program> {
    compile_internal(
        nodes,
        outputs,
        division_node_batches,
        runtime_functions,
        replacements,
        true,
    )
}

fn compile_internal(
    nodes: &[Node],
    outputs: &[usize],
    division_node_batches: &[Range<usize>],
    runtime_functions: Vec<RuntimeFunction>,
    replacements: &[ResolvedNativeSubgraph],
    retain_source_map: bool,
) -> eyre::Result<Program> {
    validate_graph(nodes, outputs)?;

    let mut native_owner = vec![None; nodes.len()];
    let mut native_activation = vec![None; nodes.len()];
    for (replacement, subgraph) in replacements.iter().enumerate() {
        for &node in &subgraph.covered {
            native_owner[node] = Some(replacement);
        }
        native_activation[*subgraph.outputs.iter().min().unwrap()] = Some(replacement);
    }
    let opaque = native_owner.iter().map(Option::is_some).collect::<Vec<_>>();

    let mut uses = vec![0_usize; nodes.len()];
    for node in nodes {
        match node {
            Node::Op(_, left, right) => {
                uses[*left] += 1;
                if left != right {
                    uses[*right] += 1;
                }
            }
            Node::BBF(_, parameters) => {
                for &parameter in parameters {
                    uses[parameter] += 1;
                }
            }
            Node::RuntimeCall { parameters, .. } => {
                for &parameter in parameters {
                    uses[parameter] += 1;
                }
            }
            _ => {}
        }
    }
    let (linear_specs, linear_skip) = linear_specs(nodes, outputs, &uses, &opaque);
    let output_set = outputs.iter().copied().collect::<HashSet<_>>();
    let mut coefficient_uses = vec![0_usize; nodes.len()];
    for (user, node) in nodes.iter().enumerate() {
        if !linear_skip[user] {
            continue;
        }
        let Node::Op(Operation::Mul, left, right) = node else {
            continue;
        };
        // This mirrors `add_linear_leaf`: when both inputs are constants, the left input is the
        // coefficient and the right input remains the value term.
        let coefficient = if matches!(nodes[*left], Node::Constant(_) | Node::MontConstant(_)) {
            Some((*left, *right))
        } else if matches!(nodes[*right], Node::Constant(_) | Node::MontConstant(_)) {
            Some((*right, *left))
        } else {
            None
        };
        if let Some((coefficient, value)) = coefficient {
            if coefficient != value {
                coefficient_uses[coefficient] += 1;
            }
        }
    }
    let coefficient_skip = coefficient_uses
        .iter()
        .enumerate()
        .map(|(index, &coefficient_uses)| {
            !opaque[index]
                && coefficient_uses != 0
                && coefficient_uses == uses[index]
                && !output_set.contains(&index)
        })
        .collect::<Vec<_>>();

    let mut pow5 = vec![None; nodes.len()];
    let mut pow5_skip = vec![false; nodes.len()];
    for (index, node) in nodes.iter().enumerate() {
        if opaque[index] {
            continue;
        }
        let Node::Op(Operation::Mul, left, right) = node else {
            continue;
        };
        for (fourth, base) in [(*left, *right), (*right, *left)] {
            if opaque[fourth] || opaque[base] {
                continue;
            }
            let Node::Op(Operation::Mul, square, same_square) = nodes[fourth] else {
                continue;
            };
            if opaque[square] || opaque[same_square] {
                continue;
            }
            if square != same_square {
                continue;
            }
            let Node::Op(Operation::Mul, first, second) = nodes[square] else {
                continue;
            };
            if first == second
                && first == base
                && uses[square] == 1
                && uses[fourth] == 1
                && !linear_skip[index]
                && !linear_skip[square]
                && !linear_skip[fourth]
            {
                pow5[index] = Some((base, square, fourth));
                pow5_skip[square] = true;
                pow5_skip[fourth] = true;
                break;
            }
        }
    }

    let mut coefficients = Vec::new();
    let mut coefficient_indices = BTreeMap::new();
    let mut instructions = Vec::new();
    let mut linear3 = Vec::new();
    let mut linear4 = Vec::new();
    let mut black_boxes = Vec::new();
    let mut native_subgraphs = Vec::new();
    let mut runtime_calls = Vec::new();
    let mut runtime_call_count = 0_usize;
    let mut node_to_value = vec![None; nodes.len()];
    let mut node_to_instruction = vec![None; nodes.len()];
    let mut value_count = 0_usize;
    let mut input_count = 0_usize;

    for (node_index, node) in nodes.iter().enumerate() {
        if let Some(replacement) = native_activation[node_index] {
            let subgraph = &replacements[replacement];
            let inputs = subgraph
                .inputs
                .iter()
                .map(|&input| {
                    node_to_value[input]
                        .ok_or_else(|| {
                            eyre!(
                                "native subgraph {:?} input node {input} was not compiled before its first output",
                                subgraph.name
                            )
                        })
                        .and_then(|value| narrow_id(value, "value ID"))
                })
                .collect::<eyre::Result<Vec<_>>>()?;
            let native = narrow_id(native_subgraphs.len(), "native subgraph ID")?;
            native_subgraphs.push(NativeInstruction {
                name: subgraph.name.clone(),
                inputs,
                output_count: subgraph.outputs.len(),
                function: subgraph.function.clone(),
            });
            for (offset, &output) in subgraph.outputs.iter().enumerate() {
                node_to_value[output] = Some(value_count + offset);
            }
            let instruction_index = instructions.len();
            for &covered in &subgraph.covered {
                node_to_instruction[covered] = Some(instruction_index);
            }
            instructions.push(Instruction::Native(native));
            value_count += subgraph.outputs.len();
            continue;
        }
        if native_owner[node_index].is_some() {
            continue;
        }
        if linear_skip[node_index] || coefficient_skip[node_index] || pow5_skip[node_index] {
            continue;
        }
        let instruction_index = instructions.len();
        let instruction = if let Some((base, square, fourth)) = pow5[node_index] {
            let base = node_to_value[base]
                .ok_or_else(|| eyre!("Pow5 base was not compiled before node {node_index}"))?;
            node_to_value[square] = Some(value_count);
            node_to_value[fourth] = Some(value_count + 1);
            node_to_value[node_index] = Some(value_count + 2);
            value_count += 3;
            Instruction::Pow5(narrow_id(base, "value ID")?)
        } else {
            let instruction = if let Some(spec) = &linear_specs[node_index] {
                let terms = spec
                    .terms
                    .iter()
                    .map(|(reference, coefficient)| {
                        let reference = node_to_value[*reference].ok_or_else(|| {
                            eyre!("linear-combination input was not compiled before node {node_index}")
                        })?;
                        let coefficient = intern_coefficient(
                            *coefficient,
                            &mut coefficients,
                            &mut coefficient_indices,
                        );
                        Ok((
                            narrow_id(reference, "value ID")?,
                            narrow_id(coefficient, "coefficient ID")?,
                        ))
                    })
                    .collect::<eyre::Result<Vec<_>>>()?;
                match terms.len() {
                    3 => {
                        let index = narrow_id(linear3.len(), "linear3 ID")?;
                        linear3.push(terms.try_into().unwrap());
                        Instruction::Linear3(index)
                    }
                    4 => {
                        let index = narrow_id(linear4.len(), "linear4 ID")?;
                        linear4.push(terms.try_into().unwrap());
                        Instruction::Linear4(index)
                    }
                    _ => unreachable!(),
                }
            } else {
                match node {
                    Node::Input(input) => {
                        input_count = input_count.max(
                            input
                                .checked_add(1)
                                .ok_or_else(|| eyre!("input index overflowed"))?,
                        );
                        Instruction::Input(*input)
                    }
                    Node::Constant(value) => Instruction::Constant(narrow_id(
                        intern_coefficient(
                            Fr::new((*value).into()),
                            &mut coefficients,
                            &mut coefficient_indices,
                        ),
                        "coefficient ID",
                    )?),
                    Node::MontConstant(value) => Instruction::Constant(narrow_id(
                        intern_coefficient(*value, &mut coefficients, &mut coefficient_indices),
                        "coefficient ID",
                    )?),
                    Node::Op(Operation::Mul, left, right) if left == right => {
                        Instruction::Square(narrow_id(node_to_value[*left].unwrap(), "value ID")?)
                    }
                    Node::Op(operation, left, right) => {
                        let left = narrow_id(node_to_value[*left].unwrap(), "value ID")?;
                        let right = narrow_id(node_to_value[*right].unwrap(), "value ID")?;
                        match operation {
                            Operation::Mul => Instruction::Mul(left, right),
                            Operation::Add => Instruction::Add(left, right),
                            Operation::Sub => Instruction::Sub(left, right),
                            _ => Instruction::Op(*operation, left, right),
                        }
                    }
                    Node::BBF(name, parameters) => {
                        let index = narrow_id(black_boxes.len(), "black-box ID")?;
                        black_boxes.push(BlackBoxInstruction {
                            name: strip_suffix_number(name),
                            parameters: parameters
                                .iter()
                                .map(|parameter| {
                                    narrow_id(node_to_value[*parameter].unwrap(), "value ID")
                                })
                                .collect::<eyre::Result<Vec<_>>>()?,
                        });
                        Instruction::BlackBox(index)
                    }
                    Node::RuntimeCall {
                        function,
                        call,
                        output,
                        output_count,
                        arena_size,
                        argument_sizes,
                        parameters,
                    } => {
                        let index = narrow_id(runtime_calls.len(), "runtime-call ID")?;
                        runtime_call_count = runtime_call_count.max(
                            call.checked_add(1)
                                .ok_or_else(|| eyre!("runtime-call ID overflowed"))?,
                        );
                        runtime_calls.push(RuntimeCallInstruction {
                            function: *function,
                            call: *call,
                            output: *output,
                            output_count: *output_count,
                            arena_size: *arena_size,
                            argument_sizes: argument_sizes.clone(),
                            parameters: parameters
                                .iter()
                                .map(|parameter| {
                                    narrow_id(node_to_value[*parameter].unwrap(), "value ID")
                                })
                                .collect::<eyre::Result<Vec<_>>>()?,
                        });
                        Instruction::RuntimeCall(index)
                    }
                }
            };
            node_to_value[node_index] = Some(value_count);
            value_count += 1;
            instruction
        };
        node_to_instruction[node_index] = Some(instruction_index);
        if let Some((_, square, fourth)) = pow5[node_index] {
            node_to_instruction[square] = Some(instruction_index);
            node_to_instruction[fourth] = Some(instruction_index);
        }
        if let Some(spec) = &linear_specs[node_index] {
            for &skipped in &spec.skip {
                node_to_instruction[skipped] = Some(instruction_index);
            }
        }
        instructions.push(instruction);
    }

    let source_map = retain_source_map.then(|| {
        let mut instruction_sources = vec![Vec::new(); instructions.len()];
        for (node, instruction) in node_to_instruction.iter().enumerate() {
            if let Some(instruction) = instruction {
                instruction_sources[*instruction].push(node);
            }
        }
        let instruction_boundary_sources = instruction_sources
            .iter()
            .map(|sources| {
                let covered = sources.iter().copied().collect::<HashSet<_>>();
                let mut boundaries = BTreeSet::new();
                for &source in sources {
                    match &nodes[source] {
                        Node::Op(_, left, right) => {
                            if !covered.contains(left) {
                                boundaries.insert(*left);
                            }
                            if !covered.contains(right) {
                                boundaries.insert(*right);
                            }
                        }
                        Node::BBF(_, parameters) | Node::RuntimeCall { parameters, .. } => {
                            boundaries.extend(
                                parameters
                                    .iter()
                                    .copied()
                                    .filter(|parameter| !covered.contains(parameter)),
                            );
                        }
                        Node::Input(_) | Node::Constant(_) | Node::MontConstant(_) => {}
                    }
                }
                boundaries.into_iter().collect()
            })
            .collect();
        let mut value_sources = vec![usize::MAX; value_count];
        for (node, value) in node_to_value.iter().enumerate() {
            if let Some(value) = value {
                value_sources[*value] = node;
            }
        }
        ProgramSourceMap {
            instruction_sources,
            instruction_boundary_sources,
            value_sources,
            node_count: nodes.len(),
        }
    });
    if source_map
        .as_ref()
        .is_some_and(|source_map| source_map.value_sources.contains(&usize::MAX))
    {
        bail!("compiled program value is missing graph-node provenance");
    }

    let outputs = outputs
        .iter()
        .map(|&output| {
            node_to_value[output]
                .ok_or_else(|| eyre!("output node {output} was not assigned a program value"))
        })
        .collect::<eyre::Result<Vec<_>>>()?;

    let mut division_batches = Vec::with_capacity(division_node_batches.len());
    for batch in division_node_batches {
        if batch.is_empty() || batch.end > nodes.len() {
            bail!("invalid division node batch {batch:?}");
        }
        let start = node_to_instruction[batch.start]
            .ok_or_else(|| eyre!("division batch starts at a skipped node"))?;
        let last = node_to_instruction[batch.end - 1]
            .ok_or_else(|| eyre!("division batch ends at a skipped node"))?;
        let instruction_batch = start..last + 1;
        if instruction_batch.len() != batch.len()
            || !instructions[instruction_batch.clone()]
                .iter()
                .all(|instruction| matches!(instruction, Instruction::Op(Operation::Div, _, _)))
        {
            bail!("division batch did not compile to contiguous division instructions");
        }
        division_batches.push(instruction_batch);
    }

    let program = Program {
        coefficients,
        instructions,
        linear3,
        linear4,
        black_boxes,
        native_subgraphs,
        runtime_functions,
        native_runtime_functions: Vec::new(),
        runtime_calls,
        runtime_call_count,
        outputs,
        division_batches,
        value_count,
        input_count,
        source_map: source_map.map_or_else(OnceLock::new, OnceLock::from),
    };
    program.validate()?;
    Ok(program)
}

impl Program {
    fn instruction_output_count(&self, instruction: &Instruction) -> usize {
        match instruction {
            Instruction::Pow5(_) => 3,
            Instruction::Native(native) => self.native_subgraphs[*native as usize].output_count,
            _ => 1,
        }
    }

    pub(crate) fn instruction_count(&self) -> usize {
        self.instructions.len()
    }

    pub(crate) fn has_customizations(&self) -> bool {
        !self.native_subgraphs.is_empty() || !self.native_runtime_functions.is_empty()
    }

    pub(crate) fn runtime_functions(&self) -> &[RuntimeFunction] {
        &self.runtime_functions
    }

    pub(crate) fn instruction_mix(&self) -> Vec<(String, usize)> {
        let mut counts = BTreeMap::<String, usize>::new();
        for instruction in &self.instructions {
            let operation = match instruction {
                Instruction::Input(_) => "input".to_owned(),
                Instruction::Constant(_) => "constant".to_owned(),
                Instruction::Mul(_, _) => "mul".to_owned(),
                Instruction::Add(_, _) => "add".to_owned(),
                Instruction::Sub(_, _) => "sub".to_owned(),
                Instruction::Op(operation, _, _) => format!("op:{operation:?}"),
                Instruction::Square(_) => "square".to_owned(),
                Instruction::Pow5(_) => "pow5".to_owned(),
                Instruction::Linear3(_) => "linear3".to_owned(),
                Instruction::Linear4(_) => "linear4".to_owned(),
                Instruction::BlackBox(black_box) => {
                    format!("black_box:{}", self.black_boxes[*black_box as usize].name)
                }
                Instruction::Native(native) => format!(
                    "native_subgraph:{}",
                    self.native_subgraphs[*native as usize].name
                ),
                Instruction::RuntimeCall(runtime_call) => {
                    let runtime_call = &self.runtime_calls[*runtime_call as usize];
                    format!(
                        "runtime_call:{}",
                        self.runtime_functions[runtime_call.function].name
                    )
                }
            };
            *counts.entry(operation).or_default() += 1;
        }
        counts.into_iter().collect()
    }

    pub(crate) fn has_source_provenance(&self) -> bool {
        self.source_map.get().is_some()
    }

    pub(crate) fn source_node_ranges(&self, instructions: Range<usize>) -> Vec<SourceNodeRange> {
        let Some(source_map) = self.source_map.get() else {
            return Vec::new();
        };
        let end = instructions.end.min(source_map.instruction_sources.len());
        if instructions.start >= end {
            return Vec::new();
        }
        source_ranges(
            source_map.instruction_sources[instructions.start..end]
                .iter()
                .flatten()
                .copied(),
        )
    }

    fn instruction_operands(&self, instruction: &Instruction) -> Vec<usize> {
        match instruction {
            Instruction::Input(_) | Instruction::Constant(_) => Vec::new(),
            Instruction::Mul(left, right)
            | Instruction::Add(left, right)
            | Instruction::Sub(left, right)
            | Instruction::Op(_, left, right) => vec![*left as usize, *right as usize],
            Instruction::Square(value) | Instruction::Pow5(value) => vec![*value as usize],
            Instruction::Linear3(linear) => self.linear3[*linear as usize]
                .iter()
                .map(|&(value, _)| value as usize)
                .collect(),
            Instruction::Linear4(linear) => self.linear4[*linear as usize]
                .iter()
                .map(|&(value, _)| value as usize)
                .collect(),
            Instruction::BlackBox(black_box) => self.black_boxes[*black_box as usize]
                .parameters
                .iter()
                .map(|&value| value as usize)
                .collect(),
            Instruction::Native(native) => self.native_subgraphs[*native as usize]
                .inputs
                .iter()
                .map(|&value| value as usize)
                .collect(),
            Instruction::RuntimeCall(runtime_call) => self.runtime_calls[*runtime_call as usize]
                .parameters
                .iter()
                .map(|&value| value as usize)
                .collect(),
        }
    }

    fn instruction_operation_label(&self, instruction: &Instruction) -> String {
        match instruction {
            Instruction::Input(_) => "input".to_owned(),
            Instruction::Constant(_) => "constant".to_owned(),
            Instruction::Mul(_, _) => "mul".to_owned(),
            Instruction::Add(_, _) => "add".to_owned(),
            Instruction::Sub(_, _) => "sub".to_owned(),
            Instruction::Op(operation, _, _) => format!("op:{operation:?}"),
            Instruction::Square(_) => "square".to_owned(),
            Instruction::Pow5(_) => "pow5".to_owned(),
            Instruction::Linear3(_) => "linear3".to_owned(),
            Instruction::Linear4(_) => "linear4".to_owned(),
            Instruction::BlackBox(black_box) => {
                format!("black_box:{}", self.black_boxes[*black_box as usize].name)
            }
            Instruction::Native(native) => format!(
                "native_subgraph:{}",
                self.native_subgraphs[*native as usize].name
            ),
            Instruction::RuntimeCall(runtime_call) => {
                let runtime_call = &self.runtime_calls[*runtime_call as usize];
                format!(
                    "runtime_call:{}",
                    self.runtime_functions[runtime_call.function].name
                )
            }
        }
    }

    fn is_structural_instruction(instruction: &Instruction) -> bool {
        !matches!(
            instruction,
            Instruction::Input(_)
                | Instruction::Constant(_)
                | Instruction::BlackBox(_)
                | Instruction::Native(_)
                | Instruction::RuntimeCall(_)
        )
    }

    fn hash_instruction_semantics(
        &self,
        instruction: &Instruction,
        hasher: &mut StableShapeHasher,
    ) {
        let label = self.instruction_operation_label(instruction);
        hasher.write(label.as_bytes());
        match instruction {
            Instruction::Linear3(linear) => {
                for &(_, coefficient) in &self.linear3[*linear as usize] {
                    hasher.write(&fr_bytes(self.coefficients[coefficient as usize]));
                }
            }
            Instruction::Linear4(linear) => {
                for &(_, coefficient) in &self.linear4[*linear as usize] {
                    hasher.write(&fr_bytes(self.coefficients[coefficient as usize]));
                }
            }
            _ => {}
        }
    }

    pub(crate) fn structural_hotspots(
        &self,
        instruction_costs: &[u64],
        trace_total_ns: u64,
        maximum: usize,
    ) -> Vec<StructuralHotspot> {
        let Some(source_map) = self.source_map.get() else {
            return Vec::new();
        };
        if instruction_costs.len() != self.instructions.len() {
            return Vec::new();
        }

        let mut instruction_values = Vec::with_capacity(self.instructions.len());
        let mut value_producers = vec![usize::MAX; self.value_count];
        let mut next_value = 0_usize;
        for (instruction, operation) in self.instructions.iter().enumerate() {
            let start = next_value;
            next_value += self.instruction_output_count(operation);
            for producer in &mut value_producers[start..next_value] {
                *producer = instruction;
            }
            instruction_values.push(start..next_value);
        }

        let mut value_users = vec![0_usize; self.value_count];
        for instruction in &self.instructions {
            let mut operands = self.instruction_operands(instruction);
            operands.sort_unstable();
            operands.dedup();
            for operand in operands {
                value_users[operand] += 1;
            }
        }
        let output_values = self.outputs.iter().copied().collect::<HashSet<_>>();

        let mut shapes = Vec::<StructuralShape>::with_capacity(self.instructions.len());
        let mut children = Vec::<Vec<usize>>::with_capacity(self.instructions.len());
        let mut groups = BTreeMap::<(StructuralShape, String), Vec<usize>>::new();
        for (instruction_index, instruction) in self.instructions.iter().enumerate() {
            let operands = self.instruction_operands(instruction);
            let mut hasher = StableShapeHasher::new();
            self.hash_instruction_semantics(instruction, &mut hasher);
            let mut boundary_ordinals = BTreeMap::<usize, usize>::new();
            let mut instruction_children = BTreeSet::new();
            for operand in operands {
                let producer = value_producers[operand];
                let producer_is_owned = producer < instruction_index
                    && Self::is_structural_instruction(&self.instructions[producer])
                    && value_users[operand] == 1
                    && !output_values.contains(&operand)
                    && instruction_values[producer].clone().all(|produced| {
                        produced == operand
                            || (value_users[produced] == 0 && !output_values.contains(&produced))
                    });
                if producer_is_owned {
                    hasher.write(b"child");
                    hasher.write(&shapes[producer].fingerprint);
                    instruction_children.insert(producer);
                } else {
                    let next_ordinal = boundary_ordinals.len();
                    let ordinal = *boundary_ordinals.entry(operand).or_insert(next_ordinal);
                    hasher.write(b"boundary");
                    hasher.write_usize(ordinal);
                    let kind = match &self.instructions[producer] {
                        Instruction::Input(_) => b"input".as_slice(),
                        Instruction::Constant(_) => b"constant".as_slice(),
                        _ => b"computed".as_slice(),
                    };
                    hasher.write(kind);
                }
            }
            let instruction_children = instruction_children.into_iter().collect::<Vec<_>>();
            let shape = StructuralShape {
                fingerprint: hasher.finish(),
                compact_instructions: 1 + instruction_children
                    .iter()
                    .map(|&child| shapes[child].compact_instructions)
                    .sum::<usize>(),
                graph_nodes: source_map.instruction_sources[instruction_index].len()
                    + instruction_children
                        .iter()
                        .map(|&child| shapes[child].graph_nodes)
                        .sum::<usize>(),
                boundary_values: boundary_ordinals.len()
                    + instruction_children
                        .iter()
                        .map(|&child| shapes[child].boundary_values)
                        .sum::<usize>(),
            };
            children.push(instruction_children);
            shapes.push(shape);
            if Self::is_structural_instruction(instruction)
                && (shape.compact_instructions >= 2 || shape.graph_nodes >= 2)
            {
                groups
                    .entry((shape, self.instruction_operation_label(instruction)))
                    .or_default()
                    .push(instruction_index);
            }
        }

        let denominator = trace_total_ns.max(1) as f64;
        let mut hotspots = groups
            .into_iter()
            .filter(|(_, roots)| roots.len() >= 2)
            .map(|((shape, root_operation), roots)| {
                let occurrence_instructions = roots
                    .iter()
                    .map(|&root| structural_closure(root, &children))
                    .collect::<Vec<_>>();
                let unique_instructions = occurrence_instructions
                    .iter()
                    .flatten()
                    .copied()
                    .collect::<BTreeSet<_>>();
                let estimated_inclusive_ns = unique_instructions
                    .iter()
                    .fold(0_u64, |sum, &i| sum.saturating_add(instruction_costs[i]));
                let samples = roots
                    .iter()
                    .zip(&occurrence_instructions)
                    .take(3)
                    .map(|(&root, instructions)| {
                        let covered_nodes = instructions
                            .iter()
                            .flat_map(|&instruction| {
                                source_map.instruction_sources[instruction].iter().copied()
                            })
                            .collect::<BTreeSet<_>>();
                        let boundary_source_nodes = instructions
                            .iter()
                            .flat_map(|&instruction| {
                                source_map.instruction_boundary_sources[instruction]
                                    .iter()
                                    .copied()
                            })
                            .filter(|node| !covered_nodes.contains(node))
                            .collect::<BTreeSet<_>>()
                            .into_iter()
                            .collect();
                        let root_source_nodes = instruction_values[root]
                            .clone()
                            .map(|value| source_map.value_sources[value])
                            .collect::<BTreeSet<_>>()
                            .into_iter()
                            .collect();
                        StructuralOccurrence {
                            root_instruction: root,
                            root_source_nodes,
                            compact_instruction_count: instructions.len(),
                            source_node_ranges: source_ranges(covered_nodes),
                            boundary_source_nodes,
                        }
                    })
                    .collect::<Vec<_>>();
                let graph_nodes_per_occurrence =
                    samples.first().map_or(shape.graph_nodes, |sample| {
                        sample
                            .source_node_ranges
                            .iter()
                            .map(|range| range.end - range.start)
                            .sum()
                    });
                let boundary_values_per_occurrence =
                    samples.first().map_or(shape.boundary_values, |sample| {
                        sample.boundary_source_nodes.len()
                    });
                StructuralHotspot {
                    fingerprint: shape
                        .fingerprint
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect(),
                    root_operation,
                    occurrences: roots.len(),
                    compact_instructions_per_occurrence: shape.compact_instructions,
                    graph_nodes_per_occurrence,
                    boundary_values_per_occurrence,
                    total_unique_compact_instructions: unique_instructions.len(),
                    estimated_inclusive_ns,
                    estimated_inclusive_percent: estimated_inclusive_ns as f64 * 100.0
                        / denominator,
                    samples,
                }
            })
            .collect::<Vec<_>>();
        hotspots.sort_by(|left, right| {
            right
                .estimated_inclusive_ns
                .cmp(&left.estimated_inclusive_ns)
                .then_with(|| right.occurrences.cmp(&left.occurrences))
                .then_with(|| left.fingerprint.cmp(&right.fingerprint))
        });
        if maximum != 0 {
            hotspots.truncate(maximum);
        }
        hotspots
    }

    fn special_instruction_profile_frame(&self, index: usize) -> Option<ProfileFrame> {
        let label = match &self.instructions[index] {
            Instruction::BlackBox(black_box) => format!(
                "instruction[{index}]:black_box:{}",
                self.black_boxes[*black_box as usize].name
            ),
            Instruction::Native(native) => format!(
                "instruction[{index}]:native_subgraph:{}",
                self.native_subgraphs[*native as usize].name
            ),
            Instruction::RuntimeCall(runtime_call) => {
                let runtime_call = &self.runtime_calls[*runtime_call as usize];
                let name = &self.runtime_functions[runtime_call.function].name;
                format!(
                    "instruction[{index}]:runtime_call:{name}:output[{}]",
                    runtime_call.output
                )
            }
            _ => return None,
        };
        Some(ProfileFrame::instruction(index, label))
    }

    pub(crate) fn with_native_runtime_functions(
        mut self,
        functions: Vec<NativeRuntimeFunction>,
    ) -> eyre::Result<Self> {
        for function in &functions {
            if function.matcher().is_empty() {
                bail!("native runtime-function matchers must not be empty");
            }
            if !self
                .runtime_functions
                .iter()
                .any(|candidate| function.matcher().matches(&candidate.name))
            {
                bail!(
                    "native runtime-function matcher {:?} matches no function in this graph",
                    function.matcher()
                );
            }
        }
        self.native_runtime_functions = functions;
        Ok(self)
    }

    pub(crate) fn input_count(&self) -> usize {
        self.input_count.max(1)
    }

    pub(crate) fn bind_black_boxes(
        &self,
        bbfs: Option<&HashMap<String, BlackBoxFunction>>,
    ) -> eyre::Result<BoundBlackBoxes> {
        if self.black_boxes.is_empty() {
            return Ok(BoundBlackBoxes {
                functions: Vec::new(),
            });
        }
        let bbfs = bbfs.ok_or_else(|| eyre!("no black box functions provided"))?;
        let functions = self
            .black_boxes
            .iter()
            .map(|black_box| {
                bbfs.get(&black_box.name)
                    .cloned()
                    .ok_or_else(|| eyre!("black box function {:?} not found", black_box.name))
            })
            .collect::<eyre::Result<Vec<_>>>()?;
        Ok(BoundBlackBoxes { functions })
    }

    /// Reorders the already-fused program into division-depth layers without expanding it back
    /// into a [`Node`] DAG. Programs produced by `compile` and `decode` are validated, so this pass
    /// only needs to calculate depths, renumber values, and build the division batch ranges.
    pub(crate) fn prepare_evaluation(mut self) -> eyre::Result<Self> {
        if !self
            .instructions
            .iter()
            .any(|instruction| matches!(instruction, Instruction::Op(Operation::Div, _, _)))
        {
            self.division_batches.clear();
            return Ok(self);
        }

        let mut value_depths = Vec::with_capacity(self.value_count);
        let mut instruction_depths = Vec::with_capacity(self.instructions.len());
        let mut max_depth = 0_usize;
        for instruction in &self.instructions {
            let value_depth = |value: u32| -> eyre::Result<usize> {
                value_depths
                    .get(value as usize)
                    .copied()
                    .ok_or_else(|| eyre!("program references unavailable value {value}"))
            };
            let depth = match instruction {
                Instruction::Input(_) | Instruction::Constant(_) => 0,
                Instruction::Mul(left, right)
                | Instruction::Add(left, right)
                | Instruction::Sub(left, right) => value_depth(*left)?.max(value_depth(*right)?),
                Instruction::Op(operation, left, right) => {
                    let depth = value_depth(*left)?.max(value_depth(*right)?);
                    if *operation == Operation::Div {
                        depth
                            .checked_add(1)
                            .ok_or_else(|| eyre!("program division depth overflowed"))?
                    } else {
                        depth
                    }
                }
                Instruction::Square(value) | Instruction::Pow5(value) => value_depth(*value)?,
                Instruction::Linear3(linear) => self.linear3[*linear as usize]
                    .iter()
                    .try_fold(0_usize, |depth, &(value, _)| {
                        Ok::<_, eyre::Report>(depth.max(value_depth(value)?))
                    })?,
                Instruction::Linear4(linear) => self.linear4[*linear as usize]
                    .iter()
                    .try_fold(0_usize, |depth, &(value, _)| {
                        Ok::<_, eyre::Report>(depth.max(value_depth(value)?))
                    })?,
                Instruction::BlackBox(black_box) => self.black_boxes[*black_box as usize]
                    .parameters
                    .iter()
                    .try_fold(0_usize, |depth, &value| {
                        Ok::<_, eyre::Report>(depth.max(value_depth(value)?))
                    })?,
                Instruction::Native(native) => self.native_subgraphs[*native as usize]
                    .inputs
                    .iter()
                    .try_fold(0_usize, |depth, &value| {
                        Ok::<_, eyre::Report>(depth.max(value_depth(value)?))
                    })?,
                Instruction::RuntimeCall(runtime_call) => self.runtime_calls
                    [*runtime_call as usize]
                    .parameters
                    .iter()
                    .try_fold(0_usize, |depth, &value| {
                        Ok::<_, eyre::Report>(depth.max(value_depth(value)?))
                    })?,
            };
            max_depth = max_depth.max(depth);
            instruction_depths.push(depth);
            let produced_values = self.instruction_output_count(instruction);
            value_depths.extend(std::iter::repeat_n(depth, produced_values));
        }
        if value_depths.len() != self.value_count {
            bail!("program value count is inconsistent");
        }

        let layer_count = max_depth + 1;
        let mut regular = vec![Vec::new(); layer_count];
        let mut divisions = vec![Vec::new(); layer_count];
        for (index, (instruction, &depth)) in self
            .instructions
            .iter()
            .zip(&instruction_depths)
            .enumerate()
        {
            if matches!(instruction, Instruction::Op(Operation::Div, _, _)) {
                divisions[depth].push(index);
            } else {
                regular[depth].push(index);
            }
        }

        let mut order = Vec::with_capacity(self.instructions.len());
        let mut division_batches = Vec::with_capacity(layer_count);
        for depth in 0..layer_count {
            if !divisions[depth].is_empty() {
                let start = order.len();
                order.extend_from_slice(&divisions[depth]);
                division_batches.push(start..order.len());
            }
            order.extend_from_slice(&regular[depth]);
        }

        let mut old_value_starts = Vec::with_capacity(self.instructions.len());
        let mut next_value = 0_usize;
        for instruction in &self.instructions {
            old_value_starts.push(next_value);
            next_value += self.instruction_output_count(instruction);
        }
        let mut value_renumber = vec![usize::MAX; self.value_count];
        let mut next_value = 0_usize;
        for &old_instruction in &order {
            let old_start = old_value_starts[old_instruction];
            let produced_values =
                self.instruction_output_count(&self.instructions[old_instruction]);
            for offset in 0..produced_values {
                value_renumber[old_start + offset] = next_value + offset;
            }
            next_value += produced_values;
        }

        let remap_value = |value: u32| -> eyre::Result<u32> {
            let remapped = value_renumber
                .get(value as usize)
                .copied()
                .filter(|&value| value != usize::MAX)
                .ok_or_else(|| eyre!("program value {value} was not scheduled"))?;
            narrow_id(remapped, "value ID")
        };

        let mut instructions = Vec::with_capacity(self.instructions.len());
        let mut linear3 = Vec::with_capacity(self.linear3.len());
        let mut linear4 = Vec::with_capacity(self.linear4.len());
        let mut black_boxes = Vec::with_capacity(self.black_boxes.len());
        let mut native_subgraphs = Vec::with_capacity(self.native_subgraphs.len());
        let mut runtime_calls = Vec::with_capacity(self.runtime_calls.len());
        let mut reordered_source_map = self.source_map.get().map(|source_map| ProgramSourceMap {
            instruction_sources: Vec::with_capacity(source_map.instruction_sources.len()),
            instruction_boundary_sources: Vec::with_capacity(
                source_map.instruction_boundary_sources.len(),
            ),
            value_sources: Vec::with_capacity(source_map.value_sources.len()),
            node_count: source_map.node_count,
        });
        for old_instruction in order {
            if let (Some(source_map), Some(reordered)) =
                (self.source_map.get(), reordered_source_map.as_mut())
            {
                reordered
                    .instruction_sources
                    .push(source_map.instruction_sources[old_instruction].clone());
                reordered
                    .instruction_boundary_sources
                    .push(source_map.instruction_boundary_sources[old_instruction].clone());
                let old_start = old_value_starts[old_instruction];
                let output_count =
                    self.instruction_output_count(&self.instructions[old_instruction]);
                reordered.value_sources.extend_from_slice(
                    &source_map.value_sources[old_start..old_start + output_count],
                );
            }
            let instruction = match &self.instructions[old_instruction] {
                Instruction::Input(input) => Instruction::Input(*input),
                Instruction::Constant(coefficient) => Instruction::Constant(*coefficient),
                Instruction::Mul(left, right) => {
                    Instruction::Mul(remap_value(*left)?, remap_value(*right)?)
                }
                Instruction::Add(left, right) => {
                    Instruction::Add(remap_value(*left)?, remap_value(*right)?)
                }
                Instruction::Sub(left, right) => {
                    Instruction::Sub(remap_value(*left)?, remap_value(*right)?)
                }
                Instruction::Op(operation, left, right) => {
                    Instruction::Op(*operation, remap_value(*left)?, remap_value(*right)?)
                }
                Instruction::Square(value) => Instruction::Square(remap_value(*value)?),
                Instruction::Pow5(value) => Instruction::Pow5(remap_value(*value)?),
                Instruction::Linear3(linear) => {
                    let terms = self.linear3[*linear as usize];
                    let index = narrow_id(linear3.len(), "linear3 ID")?;
                    linear3.push([
                        (remap_value(terms[0].0)?, terms[0].1),
                        (remap_value(terms[1].0)?, terms[1].1),
                        (remap_value(terms[2].0)?, terms[2].1),
                    ]);
                    Instruction::Linear3(index)
                }
                Instruction::Linear4(linear) => {
                    let terms = self.linear4[*linear as usize];
                    let index = narrow_id(linear4.len(), "linear4 ID")?;
                    linear4.push([
                        (remap_value(terms[0].0)?, terms[0].1),
                        (remap_value(terms[1].0)?, terms[1].1),
                        (remap_value(terms[2].0)?, terms[2].1),
                        (remap_value(terms[3].0)?, terms[3].1),
                    ]);
                    Instruction::Linear4(index)
                }
                Instruction::BlackBox(black_box) => {
                    let black_box = &self.black_boxes[*black_box as usize];
                    let index = narrow_id(black_boxes.len(), "black-box ID")?;
                    black_boxes.push(BlackBoxInstruction {
                        name: black_box.name.clone(),
                        parameters: black_box
                            .parameters
                            .iter()
                            .map(|&value| remap_value(value))
                            .collect::<eyre::Result<Vec<_>>>()?,
                    });
                    Instruction::BlackBox(index)
                }
                Instruction::Native(native) => {
                    let native = &self.native_subgraphs[*native as usize];
                    let index = narrow_id(native_subgraphs.len(), "native subgraph ID")?;
                    native_subgraphs.push(NativeInstruction {
                        name: native.name.clone(),
                        inputs: native
                            .inputs
                            .iter()
                            .map(|&value| remap_value(value))
                            .collect::<eyre::Result<Vec<_>>>()?,
                        output_count: native.output_count,
                        function: native.function.clone(),
                    });
                    Instruction::Native(index)
                }
                Instruction::RuntimeCall(runtime_call) => {
                    let runtime_call = &self.runtime_calls[*runtime_call as usize];
                    let index = narrow_id(runtime_calls.len(), "runtime-call ID")?;
                    runtime_calls.push(RuntimeCallInstruction {
                        parameters: runtime_call
                            .parameters
                            .iter()
                            .map(|&value| remap_value(value))
                            .collect::<eyre::Result<Vec<_>>>()?,
                        ..runtime_call.clone()
                    });
                    Instruction::RuntimeCall(index)
                }
            };
            instructions.push(instruction);
        }

        self.instructions = instructions;
        self.linear3 = linear3;
        self.linear4 = linear4;
        self.black_boxes = black_boxes;
        self.native_subgraphs = native_subgraphs;
        self.runtime_calls = runtime_calls;
        self.source_map = reordered_source_map.map_or_else(OnceLock::new, OnceLock::from);
        self.outputs = self
            .outputs
            .into_iter()
            .map(|output| {
                value_renumber
                    .get(output)
                    .copied()
                    .filter(|&value| value != usize::MAX)
                    .ok_or_else(|| eyre!("program output value {output} was not scheduled"))
            })
            .collect::<eyre::Result<Vec<_>>>()?;
        self.division_batches = division_batches;
        debug_assert!(self.validate().is_ok());
        Ok(self)
    }

    pub(crate) fn evaluate(
        &self,
        inputs: &[U256],
        bbfs: Option<&HashMap<String, BlackBoxFunction>>,
    ) -> eyre::Result<Vec<U256>> {
        let mut workspace = EvaluationWorkspace::default();
        self.evaluate_with_workspace(inputs, bbfs, None, &mut workspace, None)?;
        Ok(workspace.outputs)
    }

    pub(crate) fn evaluate_prepared(
        &self,
        inputs: &[U256],
        black_boxes: &BoundBlackBoxes,
        workspace: &mut EvaluationWorkspace,
    ) -> eyre::Result<()> {
        self.evaluate_with_workspace(inputs, None, Some(black_boxes), workspace, None)
    }

    pub(crate) fn evaluate_prepared_profiled(
        &self,
        inputs: &[U256],
        black_boxes: &BoundBlackBoxes,
        workspace: &mut EvaluationWorkspace,
        profile: &mut ProfileCollector,
    ) -> eyre::Result<()> {
        self.evaluate_with_workspace(inputs, None, Some(black_boxes), workspace, Some(profile))
    }

    fn evaluate_with_workspace(
        &self,
        inputs: &[U256],
        bbfs: Option<&HashMap<String, BlackBoxFunction>>,
        bound_black_boxes: Option<&BoundBlackBoxes>,
        workspace: &mut EvaluationWorkspace,
        mut profile: Option<&mut ProfileCollector>,
    ) -> eyre::Result<()> {
        let EvaluationWorkspace {
            values,
            inverses,
            inversion_scratch,
            black_box_parameters,
            native_inputs,
            native_outputs,
            runtime_parameters,
            runtime_results,
            runtime_ready,
            outputs,
        } = workspace;
        values.clear();
        values.reserve(self.value_count);
        inverses.clear();
        black_box_parameters.clear();
        native_inputs.clear();
        native_outputs.clear();
        runtime_parameters.clear();
        runtime_results.resize_with(self.runtime_call_count, Vec::new);
        runtime_ready.resize(self.runtime_call_count, false);
        runtime_ready.fill(false);
        outputs.clear();
        outputs.reserve(self.outputs.len());
        let mut batches = self.division_batches.iter().peekable();
        let mut instruction_index = 0;
        let mut profile_block_token = None;
        let mut profile_block_end = 0;

        while instruction_index < self.instructions.len() {
            if batches
                .peek()
                .is_some_and(|batch| batch.start == instruction_index)
            {
                if let Some(token) = profile_block_token.take() {
                    profile.as_deref_mut().unwrap().exit(token);
                }
                let batch = batches.next().unwrap().clone();
                let profile_token = profile.as_deref_mut().map(|profile| {
                    profile.enter(ProfileFrame::division_batch(batch.start, batch.end))
                });
                inverses.clear();
                for instruction in &self.instructions[batch.clone()] {
                    let Instruction::Op(Operation::Div, _, divisor) = instruction else {
                        unreachable!();
                    };
                    inverses.push(values[*divisor as usize]);
                }
                crate::graph::batch_inversion_u256(inverses, inversion_scratch);
                for (instruction, inverse) in
                    self.instructions[batch.clone()].iter().zip(inverses.iter())
                {
                    let Instruction::Op(Operation::Div, numerator, _) = instruction else {
                        unreachable!();
                    };
                    values.push(values[*numerator as usize] * inverse);
                }
                if let Some(token) = profile_token {
                    profile.as_deref_mut().unwrap().exit(token);
                }
                instruction_index = batch.end;
                continue;
            }

            if profile.is_some() && profile_block_token.is_none() {
                let block_size = profile.as_deref().unwrap().instruction_block_size();
                let next_batch = batches
                    .peek()
                    .map(|batch| batch.start)
                    .unwrap_or(self.instructions.len());
                profile_block_end = instruction_index
                    .saturating_add(block_size)
                    .min(next_batch)
                    .min(self.instructions.len());
                profile_block_token = Some(profile.as_deref_mut().unwrap().enter(
                    ProfileFrame::instruction_block(instruction_index, profile_block_end),
                ));
            }
            let profile_token = if profile.is_some() {
                self.special_instruction_profile_frame(instruction_index)
                    .map(|frame| profile.as_deref_mut().unwrap().enter(frame))
            } else {
                None
            };
            match &self.instructions[instruction_index] {
                Instruction::Input(input) => values.push(Fr::new(
                    inputs.get(*input).copied().unwrap_or(U256::MAX).into(),
                )),
                Instruction::Constant(coefficient) => {
                    values.push(self.coefficients[*coefficient as usize])
                }
                Instruction::Mul(left, right) => {
                    values.push(values[*left as usize] * values[*right as usize])
                }
                Instruction::Add(left, right) => {
                    values.push(values[*left as usize] + values[*right as usize])
                }
                Instruction::Sub(left, right) => {
                    values.push(values[*left as usize] - values[*right as usize])
                }
                Instruction::Op(operation, left, right) => {
                    values.push(operation.eval_fr(values[*left as usize], values[*right as usize]))
                }
                Instruction::Square(value) => values.push(values[*value as usize].square()),
                Instruction::Pow5(value) => {
                    let value = *value as usize;
                    let square = values[value].square();
                    let fourth = square.square();
                    values.push(square);
                    values.push(fourth);
                    values.push(fourth * values[value]);
                }
                Instruction::Linear3(linear) => {
                    let terms = &self.linear3[*linear as usize];
                    let [(a, ca), (b, cb), (c, cc)] = terms;
                    values.push(Fr::sum_of_products(
                        &[
                            values[*a as usize],
                            values[*b as usize],
                            values[*c as usize],
                        ],
                        &[
                            self.coefficients[*ca as usize],
                            self.coefficients[*cb as usize],
                            self.coefficients[*cc as usize],
                        ],
                    ));
                }
                Instruction::Linear4(linear) => {
                    let terms = &self.linear4[*linear as usize];
                    let [(a, ca), (b, cb), (c, cc), (d, cd)] = terms;
                    values.push(Fr::sum_of_products(
                        &[
                            values[*a as usize],
                            values[*b as usize],
                            values[*c as usize],
                            values[*d as usize],
                        ],
                        &[
                            self.coefficients[*ca as usize],
                            self.coefficients[*cb as usize],
                            self.coefficients[*cc as usize],
                            self.coefficients[*cd as usize],
                        ],
                    ));
                }
                Instruction::BlackBox(black_box) => {
                    let black_box_index = *black_box as usize;
                    let black_box = &self.black_boxes[black_box_index];
                    let function = if let Some(bound) = bound_black_boxes {
                        &bound.functions[black_box_index]
                    } else {
                        let bbfs = bbfs.ok_or_else(|| eyre!("no black box functions provided"))?;
                        bbfs.get(&black_box.name).ok_or_else(|| {
                            eyre!("black box function {:?} not found", black_box.name)
                        })?
                    };
                    black_box_parameters.clear();
                    black_box_parameters.extend(
                        black_box
                            .parameters
                            .iter()
                            .map(|&value| values[value as usize]),
                    );
                    values.push(function(black_box_parameters));
                }
                Instruction::Native(native) => {
                    let native = &self.native_subgraphs[*native as usize];
                    native_inputs.clear();
                    native_inputs.extend(native.inputs.iter().map(|&value| values[value as usize]));
                    native_outputs.clear();
                    native_outputs.resize(native.output_count, Fr::from(0_u64));
                    (native.function)(native_inputs, native_outputs)
                        .wrap_err_with(|| format!("native subgraph {:?} failed", native.name))?;
                    values.extend_from_slice(native_outputs);
                }
                Instruction::RuntimeCall(runtime_call) => {
                    let runtime_call = &self.runtime_calls[*runtime_call as usize];
                    if !runtime_ready[runtime_call.call] {
                        runtime_parameters.clear();
                        runtime_parameters.extend(
                            runtime_call
                                .parameters
                                .iter()
                                .map(|&value| values[value as usize]),
                        );
                        runtime_results[runtime_call.call] = crate::runtime::evaluate(
                            &self.runtime_functions,
                            &self.native_runtime_functions,
                            profile.as_deref_mut(),
                            crate::runtime::RuntimeInvocation {
                                function: runtime_call.function,
                                arguments: runtime_parameters,
                                argument_sizes: &runtime_call.argument_sizes,
                                arena_size: runtime_call.arena_size,
                                result_size: runtime_call.output_count,
                            },
                        )?;
                        runtime_ready[runtime_call.call] = true;
                    }
                    values.push(runtime_results[runtime_call.call][runtime_call.output]);
                }
            }
            if let Some(token) = profile_token {
                profile.as_deref_mut().unwrap().exit(token);
            }
            instruction_index += 1;
            if profile_block_token.is_some() && instruction_index == profile_block_end {
                profile
                    .as_deref_mut()
                    .unwrap()
                    .exit(profile_block_token.take().unwrap());
            }
        }

        if let Some(token) = profile_block_token {
            profile.unwrap().exit(token);
        }

        outputs.extend(
            self.outputs
                .iter()
                .map(|&output| -> U256 { values[output].into() }),
        );
        Ok(())
    }

    fn validate(&self) -> eyre::Result<()> {
        let mut next_value = 0_usize;
        for (index, instruction) in self.instructions.iter().enumerate() {
            let check_value = |reference: usize| -> eyre::Result<()> {
                if reference >= next_value {
                    bail!("program instruction {index} references unavailable value {reference}");
                }
                Ok(())
            };
            let check_coefficient = |coefficient: usize| -> eyre::Result<()> {
                if coefficient >= self.coefficients.len() {
                    bail!(
                        "program instruction {index} references missing coefficient {coefficient}"
                    );
                }
                Ok(())
            };
            match instruction {
                Instruction::Input(_) => {}
                Instruction::Constant(coefficient) => check_coefficient(*coefficient as usize)?,
                Instruction::Mul(left, right)
                | Instruction::Add(left, right)
                | Instruction::Sub(left, right)
                | Instruction::Op(_, left, right) => {
                    check_value(*left as usize)?;
                    check_value(*right as usize)?;
                }
                Instruction::Square(value) | Instruction::Pow5(value) => {
                    check_value(*value as usize)?
                }
                Instruction::Linear3(linear) => {
                    let terms = self.linear3.get(*linear as usize).ok_or_else(|| {
                        eyre!("program instruction {index} references missing linear3 {linear}")
                    })?;
                    for &(value, coefficient) in terms {
                        check_value(value as usize)?;
                        check_coefficient(coefficient as usize)?;
                    }
                }
                Instruction::Linear4(linear) => {
                    let terms = self.linear4.get(*linear as usize).ok_or_else(|| {
                        eyre!("program instruction {index} references missing linear4 {linear}")
                    })?;
                    for &(value, coefficient) in terms {
                        check_value(value as usize)?;
                        check_coefficient(coefficient as usize)?;
                    }
                }
                Instruction::BlackBox(black_box) => {
                    let black_box = self.black_boxes.get(*black_box as usize).ok_or_else(|| {
                        eyre!(
                            "program instruction {index} references missing black box {black_box}"
                        )
                    })?;
                    for &parameter in &black_box.parameters {
                        check_value(parameter as usize)?;
                    }
                }
                Instruction::Native(native) => {
                    let native = self.native_subgraphs.get(*native as usize).ok_or_else(|| {
                        eyre!(
                            "program instruction {index} references missing native subgraph {native}"
                        )
                    })?;
                    if native.output_count == 0 {
                        bail!("native subgraph {:?} has no outputs", native.name);
                    }
                    for &input in &native.inputs {
                        check_value(input as usize)?;
                    }
                }
                Instruction::RuntimeCall(runtime_call) => {
                    let runtime_call = self.runtime_calls.get(*runtime_call as usize).ok_or_else(|| {
                        eyre!("program instruction {index} references missing runtime call {runtime_call}")
                    })?;
                    if runtime_call.function >= self.runtime_functions.len() {
                        bail!(
                            "runtime call references missing function {}",
                            runtime_call.function
                        );
                    }
                    if runtime_call.call >= self.runtime_call_count {
                        bail!("runtime-call ID {} is out of bounds", runtime_call.call);
                    }
                    if runtime_call.output >= runtime_call.output_count {
                        bail!(
                            "runtime-call output {} is out of bounds",
                            runtime_call.output
                        );
                    }
                    let argument_count = runtime_call
                        .argument_sizes
                        .iter()
                        .try_fold(0_usize, |total, size| total.checked_add(*size));
                    if argument_count != Some(runtime_call.parameters.len()) {
                        bail!("runtime-call argument boundaries do not match its parameters");
                    }
                    for &parameter in &runtime_call.parameters {
                        check_value(parameter as usize)?;
                    }
                }
            }
            next_value = next_value
                .checked_add(self.instruction_output_count(instruction))
                .ok_or_else(|| eyre!("program value count overflowed"))?;
        }
        if next_value != self.value_count {
            bail!("program value count is inconsistent");
        }
        for &output in &self.outputs {
            if output >= self.value_count {
                bail!("program output value {output} is out of bounds");
            }
        }
        if let Some(source_map) = self.source_map.get() {
            if source_map.instruction_sources.len() != self.instructions.len() {
                bail!("program instruction provenance is inconsistent");
            }
            if source_map.instruction_boundary_sources.len() != self.instructions.len() {
                bail!("program instruction boundary provenance is inconsistent");
            }
            if source_map.value_sources.len() != self.value_count {
                bail!("program value provenance is inconsistent");
            }
            if source_map
                .instruction_sources
                .iter()
                .flatten()
                .chain(source_map.instruction_boundary_sources.iter().flatten())
                .chain(&source_map.value_sources)
                .any(|&node| node >= source_map.node_count)
            {
                bail!("program provenance references a missing graph node");
            }
        }
        Ok(())
    }

    pub(crate) fn encode(&self) -> eyre::Result<EncodedProgram> {
        self.validate()?;
        if !self.native_subgraphs.is_empty() || !self.native_runtime_functions.is_empty() {
            bail!("graphs with process-local native customizations cannot be serialized");
        }
        let mut next_value = 0_usize;
        let mut instructions = Vec::with_capacity(self.instructions.len());
        for instruction in &self.instructions {
            let backward = |reference: usize| {
                next_value
                    .checked_sub(reference + 1)
                    .ok_or_else(|| eyre!("program reference is not backwards"))
            };
            let instruction = match instruction {
                Instruction::Input(input) => EncodedInstruction::Input(*input),
                Instruction::Constant(coefficient) => {
                    EncodedInstruction::Constant(*coefficient as usize)
                }
                Instruction::Mul(left, right) => {
                    EncodedInstruction::Mul(backward(*left as usize)?, backward(*right as usize)?)
                }
                Instruction::Add(left, right) => {
                    EncodedInstruction::Add(backward(*left as usize)?, backward(*right as usize)?)
                }
                Instruction::Sub(left, right) => {
                    EncodedInstruction::Sub(backward(*left as usize)?, backward(*right as usize)?)
                }
                Instruction::Op(operation, left, right) => EncodedInstruction::Op(
                    *operation,
                    backward(*left as usize)?,
                    backward(*right as usize)?,
                ),
                Instruction::Square(value) => {
                    EncodedInstruction::Square(backward(*value as usize)?)
                }
                Instruction::Pow5(value) => EncodedInstruction::Pow5(backward(*value as usize)?),
                Instruction::Linear3(linear) => {
                    let terms = &self.linear3[*linear as usize];
                    EncodedInstruction::Linear3([
                        (backward(terms[0].0 as usize)?, terms[0].1 as usize),
                        (backward(terms[1].0 as usize)?, terms[1].1 as usize),
                        (backward(terms[2].0 as usize)?, terms[2].1 as usize),
                    ])
                }
                Instruction::Linear4(linear) => {
                    let terms = &self.linear4[*linear as usize];
                    EncodedInstruction::Linear4([
                        (backward(terms[0].0 as usize)?, terms[0].1 as usize),
                        (backward(terms[1].0 as usize)?, terms[1].1 as usize),
                        (backward(terms[2].0 as usize)?, terms[2].1 as usize),
                        (backward(terms[3].0 as usize)?, terms[3].1 as usize),
                    ])
                }
                Instruction::BlackBox(black_box) => {
                    let black_box = &self.black_boxes[*black_box as usize];
                    EncodedInstruction::BlackBox(
                        black_box.name.clone(),
                        black_box
                            .parameters
                            .iter()
                            .map(|&parameter| backward(parameter as usize))
                            .collect::<eyre::Result<Vec<_>>>()?,
                    )
                }
                Instruction::Native(_) => unreachable!("native subgraphs were rejected above"),
                Instruction::RuntimeCall(runtime_call) => {
                    let runtime_call = &self.runtime_calls[*runtime_call as usize];
                    EncodedInstruction::RuntimeCall {
                        function: runtime_call.function,
                        call: runtime_call.call,
                        output: runtime_call.output,
                        output_count: runtime_call.output_count,
                        arena_size: runtime_call.arena_size,
                        argument_sizes: runtime_call.argument_sizes.clone(),
                        parameters: runtime_call
                            .parameters
                            .iter()
                            .map(|&parameter| backward(parameter as usize))
                            .collect::<eyre::Result<Vec<_>>>()?,
                    }
                }
            };
            instructions.push(instruction);
            next_value += self.instruction_output_count(&self.instructions[instructions.len() - 1]);
        }

        let mut previous = 0_usize;
        let output_deltas = self
            .outputs
            .iter()
            .map(|&output| {
                let encoded = if output >= previous {
                    output
                        .checked_sub(previous)
                        .and_then(|delta| delta.checked_mul(2))
                } else {
                    previous
                        .checked_sub(output)
                        .and_then(|delta| delta.checked_mul(2))
                        .and_then(|delta| delta.checked_sub(1))
                }
                .ok_or_else(|| eyre!("program output delta overflowed"))?;
                previous = output;
                Ok(encoded)
            })
            .collect::<eyre::Result<Vec<_>>>()?;

        Ok(EncodedProgram {
            coefficients: self.coefficients.iter().copied().map(fr_bytes).collect(),
            instructions,
            output_deltas,
        })
    }

    pub(crate) fn decode(
        encoded: EncodedProgram,
        runtime_functions: Vec<RuntimeFunction>,
    ) -> eyre::Result<Self> {
        let coefficients = encoded
            .coefficients
            .into_iter()
            .map(|bytes| {
                let value = U256::from_le_bytes(bytes);
                if value >= M {
                    bail!("program coefficient is not a canonical field element");
                }
                Ok(Fr::new(value.into()))
            })
            .collect::<eyre::Result<Vec<_>>>()?;
        let mut instructions = Vec::with_capacity(encoded.instructions.len());
        let mut linear3 = Vec::new();
        let mut linear4 = Vec::new();
        let mut black_boxes = Vec::new();
        let mut runtime_calls = Vec::new();
        let mut runtime_call_count = 0_usize;
        let mut next_value = 0_usize;
        let mut input_count = 0_usize;
        for encoded_instruction in encoded.instructions {
            let absolute = |distance: usize| {
                next_value
                    .checked_sub(
                        distance
                            .checked_add(1)
                            .ok_or_else(|| eyre!("program reference distance overflowed"))?,
                    )
                    .ok_or_else(|| {
                        eyre!("program reference distance {distance} is invalid at value {next_value}")
                    })
            };
            let instruction = match encoded_instruction {
                EncodedInstruction::Input(input) => {
                    input_count = input_count.max(
                        input
                            .checked_add(1)
                            .ok_or_else(|| eyre!("input index overflowed"))?,
                    );
                    Instruction::Input(input)
                }
                EncodedInstruction::Constant(coefficient) => {
                    Instruction::Constant(narrow_id(coefficient, "coefficient ID")?)
                }
                EncodedInstruction::Mul(left, right) => Instruction::Mul(
                    narrow_id(absolute(left)?, "value ID")?,
                    narrow_id(absolute(right)?, "value ID")?,
                ),
                EncodedInstruction::Add(left, right) => Instruction::Add(
                    narrow_id(absolute(left)?, "value ID")?,
                    narrow_id(absolute(right)?, "value ID")?,
                ),
                EncodedInstruction::Sub(left, right) => Instruction::Sub(
                    narrow_id(absolute(left)?, "value ID")?,
                    narrow_id(absolute(right)?, "value ID")?,
                ),
                EncodedInstruction::Op(operation, left, right) => Instruction::Op(
                    operation,
                    narrow_id(absolute(left)?, "value ID")?,
                    narrow_id(absolute(right)?, "value ID")?,
                ),
                EncodedInstruction::Square(value) => {
                    Instruction::Square(narrow_id(absolute(value)?, "value ID")?)
                }
                EncodedInstruction::Pow5(value) => {
                    Instruction::Pow5(narrow_id(absolute(value)?, "value ID")?)
                }
                EncodedInstruction::Linear3(terms) => {
                    let index = narrow_id(linear3.len(), "linear3 ID")?;
                    linear3.push([
                        (
                            narrow_id(absolute(terms[0].0)?, "value ID")?,
                            narrow_id(terms[0].1, "coefficient ID")?,
                        ),
                        (
                            narrow_id(absolute(terms[1].0)?, "value ID")?,
                            narrow_id(terms[1].1, "coefficient ID")?,
                        ),
                        (
                            narrow_id(absolute(terms[2].0)?, "value ID")?,
                            narrow_id(terms[2].1, "coefficient ID")?,
                        ),
                    ]);
                    Instruction::Linear3(index)
                }
                EncodedInstruction::Linear4(terms) => {
                    let index = narrow_id(linear4.len(), "linear4 ID")?;
                    linear4.push([
                        (
                            narrow_id(absolute(terms[0].0)?, "value ID")?,
                            narrow_id(terms[0].1, "coefficient ID")?,
                        ),
                        (
                            narrow_id(absolute(terms[1].0)?, "value ID")?,
                            narrow_id(terms[1].1, "coefficient ID")?,
                        ),
                        (
                            narrow_id(absolute(terms[2].0)?, "value ID")?,
                            narrow_id(terms[2].1, "coefficient ID")?,
                        ),
                        (
                            narrow_id(absolute(terms[3].0)?, "value ID")?,
                            narrow_id(terms[3].1, "coefficient ID")?,
                        ),
                    ]);
                    Instruction::Linear4(index)
                }
                EncodedInstruction::BlackBox(name, parameters) => {
                    let index = narrow_id(black_boxes.len(), "black-box ID")?;
                    black_boxes.push(BlackBoxInstruction {
                        name,
                        parameters: parameters
                            .into_iter()
                            .map(|parameter| narrow_id(absolute(parameter)?, "value ID"))
                            .collect::<eyre::Result<Vec<_>>>()?,
                    });
                    Instruction::BlackBox(index)
                }
                EncodedInstruction::RuntimeCall {
                    function,
                    call,
                    output,
                    output_count,
                    arena_size,
                    argument_sizes,
                    parameters,
                } => {
                    let index = narrow_id(runtime_calls.len(), "runtime-call ID")?;
                    runtime_call_count = runtime_call_count.max(
                        call.checked_add(1)
                            .ok_or_else(|| eyre!("runtime-call ID overflowed"))?,
                    );
                    runtime_calls.push(RuntimeCallInstruction {
                        function,
                        call,
                        output,
                        output_count,
                        arena_size,
                        argument_sizes,
                        parameters: parameters
                            .into_iter()
                            .map(|parameter| narrow_id(absolute(parameter)?, "value ID"))
                            .collect::<eyre::Result<Vec<_>>>()?,
                    });
                    Instruction::RuntimeCall(index)
                }
            };
            next_value = next_value
                .checked_add(if matches!(instruction, Instruction::Pow5(_)) {
                    3
                } else {
                    1
                })
                .ok_or_else(|| eyre!("program value count overflowed"))?;
            instructions.push(instruction);
        }

        let mut previous = 0_usize;
        let outputs = encoded
            .output_deltas
            .into_iter()
            .map(|delta| {
                let output = if delta & 1 == 0 {
                    previous.checked_add(delta / 2)
                } else {
                    previous.checked_sub(delta / 2 + 1)
                }
                .ok_or_else(|| eyre!("program output delta is invalid"))?;
                previous = output;
                Ok(output)
            })
            .collect::<eyre::Result<Vec<_>>>()?;

        let program = Self {
            coefficients,
            instructions,
            linear3,
            linear4,
            black_boxes,
            native_subgraphs: Vec::new(),
            runtime_functions,
            native_runtime_functions: Vec::new(),
            runtime_calls,
            runtime_call_count,
            outputs,
            division_batches: Vec::new(),
            value_count: next_value,
            input_count,
            source_map: OnceLock::new(),
        };
        program
            .validate()
            .wrap_err("invalid encoded witness program")?;
        Ok(program)
    }

    /// Attaches provenance for the deterministic compatibility DAG produced by [`Self::to_nodes`].
    /// This keeps profile node IDs useful for fused files without serializing a second graph.
    pub(crate) fn ensure_compatibility_source_map(&self) -> eyre::Result<()> {
        if self.source_map.get().is_some() {
            return Ok(());
        }
        let mut instruction_sources = Vec::with_capacity(self.instructions.len());
        let mut value_sources = Vec::with_capacity(self.value_count);
        let mut next_node = self.coefficients.len();
        for instruction in &self.instructions {
            let added_nodes = match instruction {
                Instruction::Constant(coefficient) => {
                    instruction_sources.push(vec![*coefficient as usize]);
                    value_sources.push(*coefficient as usize);
                    continue;
                }
                Instruction::Input(_)
                | Instruction::Mul(_, _)
                | Instruction::Add(_, _)
                | Instruction::Sub(_, _)
                | Instruction::Op(_, _, _)
                | Instruction::Square(_)
                | Instruction::BlackBox(_)
                | Instruction::RuntimeCall(_) => 1,
                Instruction::Pow5(_) => 3,
                Instruction::Linear3(_) => 5,
                Instruction::Linear4(_) => 7,
                Instruction::Native(native) => {
                    bail!(
                        "native subgraph {:?} has no compatibility-DAG provenance",
                        self.native_subgraphs[*native as usize].name
                    )
                }
            };
            let sources = (next_node..next_node + added_nodes).collect::<Vec<_>>();
            match instruction {
                Instruction::Pow5(_) => value_sources.extend_from_slice(&sources),
                _ => value_sources.push(*sources.last().unwrap()),
            }
            instruction_sources.push(sources);
            next_node += added_nodes;
        }
        let instruction_boundary_sources = self
            .instructions
            .iter()
            .map(|instruction| {
                let mut boundaries = self
                    .instruction_operands(instruction)
                    .into_iter()
                    .map(|value| value_sources[value])
                    .collect::<BTreeSet<_>>();
                match instruction {
                    Instruction::Linear3(linear) => boundaries.extend(
                        self.linear3[*linear as usize]
                            .iter()
                            .map(|&(_, coefficient)| coefficient as usize),
                    ),
                    Instruction::Linear4(linear) => boundaries.extend(
                        self.linear4[*linear as usize]
                            .iter()
                            .map(|&(_, coefficient)| coefficient as usize),
                    ),
                    _ => {}
                }
                boundaries.into_iter().collect()
            })
            .collect();
        let source_map = ProgramSourceMap {
            instruction_sources,
            instruction_boundary_sources,
            value_sources,
            node_count: next_node,
        };
        let _ = self.source_map.set(source_map);
        self.validate()?;
        Ok(())
    }

    /// Rebuilds a semantically equivalent Node DAG for the public compatibility fields. Runtime
    /// evaluation continues to use the compact Program after this DAG has been prepared/recompiled.
    pub(crate) fn to_nodes(&self) -> eyre::Result<(Vec<Node>, Vec<usize>)> {
        self.validate()?;
        // Materialize the coefficient pool once. Reusing these nodes avoids turning every
        // linear-combination term into its own 32-byte public `MontConstant` allocation.
        let mut nodes = self
            .coefficients
            .iter()
            .copied()
            .map(Node::MontConstant)
            .collect::<Vec<_>>();
        let coefficient_nodes = (0..self.coefficients.len()).collect::<Vec<_>>();
        let mut value_nodes = Vec::with_capacity(self.value_count);
        for instruction in &self.instructions {
            let push = |node: Node, nodes: &mut Vec<Node>| {
                let index = nodes.len();
                nodes.push(node);
                index
            };
            match instruction {
                Instruction::Input(input) => {
                    value_nodes.push(push(Node::Input(*input), &mut nodes));
                }
                Instruction::Constant(coefficient) => {
                    value_nodes.push(coefficient_nodes[*coefficient as usize])
                }
                Instruction::Mul(left, right) => value_nodes.push(push(
                    Node::Op(
                        Operation::Mul,
                        value_nodes[*left as usize],
                        value_nodes[*right as usize],
                    ),
                    &mut nodes,
                )),
                Instruction::Add(left, right) => value_nodes.push(push(
                    Node::Op(
                        Operation::Add,
                        value_nodes[*left as usize],
                        value_nodes[*right as usize],
                    ),
                    &mut nodes,
                )),
                Instruction::Sub(left, right) => value_nodes.push(push(
                    Node::Op(
                        Operation::Sub,
                        value_nodes[*left as usize],
                        value_nodes[*right as usize],
                    ),
                    &mut nodes,
                )),
                Instruction::Op(operation, left, right) => value_nodes.push(push(
                    Node::Op(
                        *operation,
                        value_nodes[*left as usize],
                        value_nodes[*right as usize],
                    ),
                    &mut nodes,
                )),
                Instruction::Square(value) => value_nodes.push(push(
                    Node::Op(
                        Operation::Mul,
                        value_nodes[*value as usize],
                        value_nodes[*value as usize],
                    ),
                    &mut nodes,
                )),
                Instruction::Pow5(value) => {
                    let base = value_nodes[*value as usize];
                    let square = push(Node::Op(Operation::Mul, base, base), &mut nodes);
                    let fourth = push(Node::Op(Operation::Mul, square, square), &mut nodes);
                    let fifth = push(Node::Op(Operation::Mul, fourth, base), &mut nodes);
                    value_nodes.extend([square, fourth, fifth]);
                }
                Instruction::Linear3(linear) => value_nodes.push(expand_linear(
                    &self.linear3[*linear as usize],
                    &coefficient_nodes,
                    &value_nodes,
                    &mut nodes,
                )),
                Instruction::Linear4(linear) => value_nodes.push(expand_linear(
                    &self.linear4[*linear as usize],
                    &coefficient_nodes,
                    &value_nodes,
                    &mut nodes,
                )),
                Instruction::BlackBox(black_box) => {
                    let black_box = &self.black_boxes[*black_box as usize];
                    value_nodes.push(push(
                        Node::BBF(
                            black_box.name.clone(),
                            black_box
                                .parameters
                                .iter()
                                .map(|&parameter| value_nodes[parameter as usize])
                                .collect(),
                        ),
                        &mut nodes,
                    ));
                }
                Instruction::Native(native) => {
                    bail!(
                        "native subgraph {:?} cannot be expanded back into graph nodes",
                        self.native_subgraphs[*native as usize].name
                    );
                }
                Instruction::RuntimeCall(runtime_call) => {
                    let runtime_call = &self.runtime_calls[*runtime_call as usize];
                    value_nodes.push(push(
                        Node::RuntimeCall {
                            function: runtime_call.function,
                            call: runtime_call.call,
                            output: runtime_call.output,
                            output_count: runtime_call.output_count,
                            arena_size: runtime_call.arena_size,
                            argument_sizes: runtime_call.argument_sizes.clone(),
                            parameters: runtime_call
                                .parameters
                                .iter()
                                .map(|&parameter| value_nodes[parameter as usize])
                                .collect(),
                        },
                        &mut nodes,
                    ));
                }
            }
        }
        let outputs = self
            .outputs
            .iter()
            .map(|&output| value_nodes[output])
            .collect();
        Ok((nodes, outputs))
    }
}

fn structural_closure(root: usize, children: &[Vec<usize>]) -> Vec<usize> {
    let mut closure = BTreeSet::new();
    let mut pending = vec![root];
    while let Some(instruction) = pending.pop() {
        if closure.insert(instruction) {
            pending.extend_from_slice(&children[instruction]);
        }
    }
    closure.into_iter().collect()
}

fn source_ranges(nodes: impl IntoIterator<Item = usize>) -> Vec<SourceNodeRange> {
    let nodes = nodes.into_iter().collect::<BTreeSet<_>>();
    let mut ranges = Vec::<SourceNodeRange>::new();
    for node in nodes {
        if let Some(last) = ranges.last_mut() {
            if last.end == node {
                last.end += 1;
                continue;
            }
        }
        ranges.push(SourceNodeRange {
            start: node,
            end: node + 1,
        });
    }
    ranges
}

fn expand_linear<const N: usize>(
    terms: &[(u32, u32); N],
    coefficient_nodes: &[usize],
    value_nodes: &[usize],
    nodes: &mut Vec<Node>,
) -> usize {
    let mut products = Vec::with_capacity(N);
    for &(value, coefficient) in terms {
        let product = nodes.len();
        nodes.push(Node::Op(
            Operation::Mul,
            coefficient_nodes[coefficient as usize],
            value_nodes[value as usize],
        ));
        products.push(product);
    }
    let mut result = products[0];
    for &product in &products[1..] {
        let addition = nodes.len();
        nodes.push(Node::Op(Operation::Add, result, product));
        result = addition;
    }
    result
}

fn fr_bytes(value: Fr) -> [u8; 32] {
    let value: U256 = value.into();
    value.to_le_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_instruction_stays_compact() {
        assert!(std::mem::size_of::<Instruction>() <= 16);
    }

    #[test]
    fn compact_program_schedules_divisions_without_recompiling() {
        let nodes = vec![
            Node::Input(0),
            Node::Input(1),
            Node::Input(2),
            Node::Op(Operation::Add, 0, 1),
            Node::Op(Operation::Sub, 1, 2),
            Node::Op(Operation::Div, 0, 3),
            Node::Op(Operation::Div, 2, 4),
            Node::Op(Operation::Add, 5, 6),
            Node::Op(Operation::Div, 7, 1),
            Node::Op(Operation::Mul, 8, 8),
            Node::Op(Operation::Mul, 9, 9),
            Node::Op(Operation::Mul, 10, 8),
        ];
        let outputs = vec![5, 6, 7, 8, 9, 10, 11];
        let original = compile(&nodes, &outputs, &[], Vec::new()).unwrap();
        let prepared = original.clone().prepare_evaluation().unwrap();
        assert_eq!(prepared.instruction_count(), original.instruction_count());
        assert_eq!(prepared.division_batches.len(), 2);
        assert_eq!(prepared.division_batches[0].len(), 2);
        assert_eq!(prepared.division_batches[1].len(), 1);

        let inputs = [U256::from(6_u64), U256::from(5_u64), U256::from(2_u64)];
        assert_eq!(
            prepared.evaluate(&inputs, None).unwrap(),
            original.evaluate(&inputs, None).unwrap()
        );
        let (prepared_nodes, prepared_outputs) = prepared.to_nodes().unwrap();
        assert_eq!(
            crate::graph::evaluate(&prepared_nodes, &inputs, &prepared_outputs, None).unwrap(),
            original.evaluate(&inputs, None).unwrap()
        );
    }

    #[test]
    fn black_box_suffix_normalization_matches_legacy_evaluator() {
        assert_eq!(strip_suffix_number("bbf_inv_17"), "bbf_inv");
        assert_eq!(strip_suffix_number("bbf_inv_"), "bbf_inv");
        assert_eq!(strip_suffix_number("bbf_inv_x"), "bbf_inv_x");
    }

    #[test]
    fn fused_program_round_trips_and_preserves_intermediate_pow_outputs() {
        let nodes = vec![
            Node::Input(0),
            Node::Input(1),
            Node::MontConstant(Fr::from(7_u64)),
            Node::Op(Operation::Mul, 0, 2),
            Node::Op(Operation::Sub, 3, 1),
            Node::Op(Operation::Add, 4, 0),
            Node::Op(Operation::Mul, 5, 5),
            Node::Op(Operation::Mul, 6, 6),
            Node::Op(Operation::Mul, 7, 5),
        ];
        let outputs = vec![5, 6, 7, 8];
        let program = compile(&nodes, &outputs, &[], Vec::new()).unwrap();
        assert!(program
            .instructions
            .iter()
            .any(|instruction| matches!(instruction, Instruction::Linear3(_))));
        assert!(program
            .instructions
            .iter()
            .any(|instruction| matches!(instruction, Instruction::Pow5(_))));

        let decoded = Program::decode(program.encode().unwrap(), Vec::new()).unwrap();
        let inputs = [U256::from(3_u64), U256::from(2_u64)];
        assert_eq!(
            crate::graph::evaluate(&nodes, &inputs, &outputs, None).unwrap(),
            decoded.evaluate(&inputs, None).unwrap()
        );
        let (expanded, expanded_outputs) = decoded.to_nodes().unwrap();
        let recompiled = compile(&expanded, &expanded_outputs, &[], Vec::new()).unwrap();
        assert_eq!(recompiled.instructions.len(), decoded.instructions.len());
        assert_eq!(
            crate::graph::evaluate(&nodes, &inputs, &outputs, None).unwrap(),
            crate::graph::evaluate(&expanded, &inputs, &expanded_outputs, None).unwrap()
        );
    }

    #[test]
    fn decode_rejects_forward_references_and_noncanonical_coefficients() {
        let invalid_reference = EncodedProgram {
            coefficients: Vec::new(),
            instructions: vec![EncodedInstruction::Square(0)],
            output_deltas: vec![0],
        };
        assert!(Program::decode(invalid_reference, Vec::new()).is_err());

        let invalid_coefficient = EncodedProgram {
            coefficients: vec![M.to_le_bytes()],
            instructions: vec![EncodedInstruction::Constant(0)],
            output_deltas: vec![0],
        };
        assert!(Program::decode(invalid_coefficient, Vec::new()).is_err());
    }

    #[test]
    fn linear_fusion_keeps_an_aliased_constant_term() {
        let nodes = vec![
            Node::MontConstant(Fr::from(3_u64)),
            Node::Input(0),
            Node::Input(1),
            Node::Op(Operation::Add, 1, 2),
            Node::Op(Operation::Mul, 0, 0),
            Node::Op(Operation::Add, 4, 3),
        ];
        let outputs = [5];
        let inputs = [U256::from(4_u64), U256::from(5_u64)];
        let program = compile(&nodes, &outputs, &[], Vec::new()).unwrap();
        assert_eq!(
            program.evaluate(&inputs, None).unwrap(),
            crate::graph::evaluate(&nodes, &inputs, &outputs, None).unwrap()
        );
    }

    #[test]
    fn pow5_does_not_consume_a_linear_fusion_term() {
        let nodes = vec![
            Node::MontConstant(Fr::from(3_u64)),
            Node::Op(Operation::Mul, 0, 0),
            Node::Op(Operation::Mul, 1, 1),
            Node::Op(Operation::Mul, 2, 0),
            Node::Input(0),
            Node::Input(1),
            Node::Op(Operation::Add, 4, 5),
            Node::Op(Operation::Add, 3, 6),
        ];
        let outputs = [7];
        let inputs = [U256::from(4_u64), U256::from(5_u64)];
        let program = compile(&nodes, &outputs, &[], Vec::new()).unwrap();
        assert_eq!(
            program.evaluate(&inputs, None).unwrap(),
            crate::graph::evaluate(&nodes, &inputs, &outputs, None).unwrap()
        );
    }

    #[test]
    fn deep_linear_chain_compiles_without_recursion() {
        let mut nodes = vec![Node::Input(0)];
        for _ in 0..30_000 {
            let previous = nodes.len() - 1;
            nodes.push(Node::Op(Operation::Add, previous, 0));
        }
        let outputs = [nodes.len() - 1];
        let program = compile(&nodes, &outputs, &[], Vec::new()).unwrap();
        let decoded = Program::decode(program.encode().unwrap(), Vec::new()).unwrap();
        let (expanded, expanded_outputs) = decoded.to_nodes().unwrap();
        compile(&expanded, &expanded_outputs, &[], Vec::new()).unwrap();
    }
}
