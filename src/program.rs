use std::{
    collections::{BTreeMap, HashMap, HashSet},
    ops::Range,
};

use ark_bn254::Fr;
use ark_ff::Field;
use eyre::{bail, eyre, Context as _};
use ruint::aliases::U256;
use serde::{Deserialize, Serialize};

use crate::{
    graph::{Node, Operation},
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
    outputs: Vec<usize>,
    division_batches: Vec<Range<usize>>,
    value_count: usize,
    input_count: usize,
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
}

#[derive(Debug, Clone)]
struct BlackBoxInstruction {
    name: String,
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
}

#[derive(Default)]
struct LinearSpec {
    terms: Vec<(usize, Fr)>,
    skip: Vec<usize>,
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
    spec: &mut LinearSpec,
) {
    // Large generated graphs can contain very deep single-use addition chains. Keep this traversal
    // iterative so valid legacy or fused input cannot overflow the Rust call stack during init.
    let mut pending = vec![(index, sign, true)];
    while let Some((index, sign, flatten)) = pending.pop() {
        let children = if flatten {
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
                    && !outputs.contains(&child);
                if inline {
                    spec.skip.push(child);
                }
                pending.push((child, child_sign, inline));
            }
        } else {
            add_linear_leaf(index, sign, nodes, uses, outputs, spec);
        }
    }
}

fn add_linear_leaf(
    index: usize,
    sign: Fr,
    nodes: &[Node],
    uses: &[usize],
    outputs: &HashSet<usize>,
    spec: &mut LinearSpec,
) {
    if uses[index] == 1 && !outputs.contains(&index) {
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
            _ => {}
        }
    }

    let mut specs = (0..nodes.len()).map(|_| None).collect::<Vec<_>>();
    let mut skip = vec![false; nodes.len()];
    for (index, node) in nodes.iter().enumerate() {
        if !matches!(node, Node::Op(Operation::Add | Operation::Sub, _, _)) {
            continue;
        }
        let is_inline_child = uses[index] == 1
            && !output_set.contains(&index)
            && sole_user[index].is_some_and(|user| {
                matches!(nodes[user], Node::Op(Operation::Add | Operation::Sub, _, _))
            });
        if is_inline_child {
            continue;
        }

        let mut spec = LinearSpec::default();
        add_linear_terms(index, Fr::from(1_u64), nodes, uses, &output_set, &mut spec);
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
) -> eyre::Result<Program> {
    validate_graph(nodes, outputs)?;

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
            _ => {}
        }
    }
    let (linear_specs, linear_skip) = linear_specs(nodes, outputs, &uses);
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
            coefficient_uses != 0 && coefficient_uses == uses[index] && !output_set.contains(&index)
        })
        .collect::<Vec<_>>();

    let mut pow5 = vec![None; nodes.len()];
    let mut pow5_skip = vec![false; nodes.len()];
    for (index, node) in nodes.iter().enumerate() {
        let Node::Op(Operation::Mul, left, right) = node else {
            continue;
        };
        for (fourth, base) in [(*left, *right), (*right, *left)] {
            let Node::Op(Operation::Mul, square, same_square) = nodes[fourth] else {
                continue;
            };
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
    let mut node_to_value = vec![None; nodes.len()];
    let mut node_to_instruction = vec![None; nodes.len()];
    let mut value_count = 0_usize;
    let mut input_count = 0_usize;

    for (node_index, node) in nodes.iter().enumerate() {
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
                }
            };
            node_to_value[node_index] = Some(value_count);
            value_count += 1;
            instruction
        };
        node_to_instruction[node_index] = Some(instruction_index);
        instructions.push(instruction);
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
        outputs,
        division_batches,
        value_count,
        input_count,
    };
    program.validate()?;
    Ok(program)
}

impl Program {
    pub(crate) fn instruction_count(&self) -> usize {
        self.instructions.len()
    }

    pub(crate) fn input_count(&self) -> usize {
        self.input_count.max(1)
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
            };
            max_depth = max_depth.max(depth);
            instruction_depths.push(depth);
            let produced_values = if matches!(instruction, Instruction::Pow5(_)) {
                3
            } else {
                1
            };
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
            next_value += if matches!(instruction, Instruction::Pow5(_)) {
                3
            } else {
                1
            };
        }
        let mut value_renumber = vec![usize::MAX; self.value_count];
        let mut next_value = 0_usize;
        for &old_instruction in &order {
            let old_start = old_value_starts[old_instruction];
            let produced_values =
                if matches!(self.instructions[old_instruction], Instruction::Pow5(_)) {
                    3
                } else {
                    1
                };
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
        for old_instruction in order {
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
            };
            instructions.push(instruction);
        }

        self.instructions = instructions;
        self.linear3 = linear3;
        self.linear4 = linear4;
        self.black_boxes = black_boxes;
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
        let mut values = Vec::with_capacity(self.value_count);
        let mut inverses = Vec::new();
        let mut inversion_scratch = Vec::new();
        let mut black_box_parameters = Vec::new();
        let mut batches = self.division_batches.iter().peekable();
        let mut instruction_index = 0;

        while instruction_index < self.instructions.len() {
            if batches
                .peek()
                .is_some_and(|batch| batch.start == instruction_index)
            {
                let batch = batches.next().unwrap().clone();
                inverses.clear();
                for instruction in &self.instructions[batch.clone()] {
                    let Instruction::Op(Operation::Div, _, divisor) = instruction else {
                        unreachable!();
                    };
                    inverses.push(values[*divisor as usize]);
                }
                crate::graph::batch_inversion_u256(&mut inverses, &mut inversion_scratch);
                for (instruction, inverse) in self.instructions[batch.clone()].iter().zip(&inverses)
                {
                    let Instruction::Op(Operation::Div, numerator, _) = instruction else {
                        unreachable!();
                    };
                    values.push(values[*numerator as usize] * inverse);
                }
                instruction_index = batch.end;
                continue;
            }

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
                    let black_box = &self.black_boxes[*black_box as usize];
                    let bbfs = bbfs.ok_or_else(|| eyre!("no black box functions provided"))?;
                    let function = bbfs.get(&black_box.name).ok_or_else(|| {
                        eyre!("black box function {:?} not found", black_box.name)
                    })?;
                    black_box_parameters.clear();
                    black_box_parameters.extend(
                        black_box
                            .parameters
                            .iter()
                            .map(|&value| values[value as usize]),
                    );
                    values.push(function(&black_box_parameters));
                }
            }
            instruction_index += 1;
        }

        Ok(self
            .outputs
            .iter()
            .map(|&output| values[output].into())
            .collect())
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
            }
            next_value = next_value
                .checked_add(if matches!(instruction, Instruction::Pow5(_)) {
                    3
                } else {
                    1
                })
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
        Ok(())
    }

    pub(crate) fn encode(&self) -> eyre::Result<EncodedProgram> {
        self.validate()?;
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
            };
            instructions.push(instruction);
            next_value += if matches!(
                self.instructions[instructions.len() - 1],
                Instruction::Pow5(_)
            ) {
                3
            } else {
                1
            };
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

    pub(crate) fn decode(encoded: EncodedProgram) -> eyre::Result<Self> {
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
            outputs,
            division_batches: Vec::new(),
            value_count: next_value,
            input_count,
        };
        program
            .validate()
            .wrap_err("invalid encoded witness program")?;
        Ok(program)
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
        let original = compile(&nodes, &outputs, &[]).unwrap();
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
        let program = compile(&nodes, &outputs, &[]).unwrap();
        assert!(program
            .instructions
            .iter()
            .any(|instruction| matches!(instruction, Instruction::Linear3(_))));
        assert!(program
            .instructions
            .iter()
            .any(|instruction| matches!(instruction, Instruction::Pow5(_))));

        let decoded = Program::decode(program.encode().unwrap()).unwrap();
        let inputs = [U256::from(3_u64), U256::from(2_u64)];
        assert_eq!(
            crate::graph::evaluate(&nodes, &inputs, &outputs, None).unwrap(),
            decoded.evaluate(&inputs, None).unwrap()
        );
        let (expanded, expanded_outputs) = decoded.to_nodes().unwrap();
        let recompiled = compile(&expanded, &expanded_outputs, &[]).unwrap();
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
        assert!(Program::decode(invalid_reference).is_err());

        let invalid_coefficient = EncodedProgram {
            coefficients: vec![M.to_le_bytes()],
            instructions: vec![EncodedInstruction::Constant(0)],
            output_deltas: vec![0],
        };
        assert!(Program::decode(invalid_coefficient).is_err());
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
        let program = compile(&nodes, &outputs, &[]).unwrap();
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
        let program = compile(&nodes, &outputs, &[]).unwrap();
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
        let program = compile(&nodes, &outputs, &[]).unwrap();
        let decoded = Program::decode(program.encode().unwrap()).unwrap();
        let (expanded, expanded_outputs) = decoded.to_nodes().unwrap();
        compile(&expanded, &expanded_outputs, &[]).unwrap();
    }
}
