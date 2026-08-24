use std::{cmp::Ordering, collections::HashMap, ops::Range, ops::Shr};

use crate::{BlackBoxFunction, M};
use ark_bn254::Fr;
use eyre::bail;
use num_bigint::BigUint;
use rand::Rng;
use ruint::aliases::U256;
use ruint::uint;
use serde::{Deserialize, Serialize};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};

fn ark_se<S, A: CanonicalSerialize>(a: &A, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let mut bytes = vec![];
    a.serialize_with_mode(&mut bytes, Compress::Yes)
        .map_err(serde::ser::Error::custom)?;
    s.serialize_bytes(&bytes)
}

fn ark_de<'de, D, A: CanonicalDeserialize>(data: D) -> Result<A, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let s: Vec<u8> = serde::de::Deserialize::deserialize(data)?;
    let a = A::deserialize_with_mode(s.as_slice(), Compress::Yes, Validate::Yes);
    a.map_err(serde::de::Error::custom)
}

#[derive(Hash, PartialEq, Eq, Debug, Clone, Copy, Serialize, Deserialize)]
pub enum Operation {
    Mul,
    MMul,
    Add,
    Sub,
    Eq,
    Neq,
    Lt,
    Gt,
    Leq,
    Geq,
    Lor,
    Shl,
    Shr,
    Band,
    Neg,
    Inv,
    Div,
    Mod,
    Pow,
    Land,
    IDiv,
    // Keep new variants at the end so existing postcard graph files remain compatible.
    Bor,
    Bxor,
    Bnot,
    Lnot,
    /// Division used while lowering eager select branches; zero maps to zero on the unselected path.
    SafeDiv,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Node {
    Input(usize),
    Constant(U256),
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    MontConstant(Fr),
    Op(Operation, usize, usize),
    BBF(String, Vec<usize>),
    RuntimeCall {
        function: usize,
        call: usize,
        output: usize,
        output_count: usize,
        arena_size: usize,
        parameters: Vec<usize>,
    },
}

#[derive(Debug, Default, Clone)]
pub(crate) struct EvaluationPlan {
    division_batches: Vec<Range<usize>>,
}

impl EvaluationPlan {
    pub(crate) fn division_batches(&self) -> &[Range<usize>] {
        &self.division_batches
    }
}

/// Reorders independent nodes into division-depth layers. Each division block can then use one
/// field inversion for the whole block, while all node references remain backwards.
pub(crate) fn prepare_evaluation(
    nodes: &mut Vec<Node>,
    outputs: &mut [usize],
) -> eyre::Result<EvaluationPlan> {
    let mut depths = Vec::<usize>::with_capacity(nodes.len());
    let mut division_count = 0;
    for (index, node) in nodes.iter().enumerate() {
        let referenced_depth = |reference: usize| -> eyre::Result<usize> {
            if reference >= index {
                bail!("graph node {index} references non-earlier node {reference}");
            }
            Ok(depths[reference])
        };
        let depth = match node {
            Node::Input(_) | Node::Constant(_) | Node::MontConstant(_) => 0,
            Node::Op(operation, left, right) => {
                let depth = referenced_depth(*left)?.max(referenced_depth(*right)?);
                if *operation == Operation::Div {
                    division_count += 1;
                    depth + 1
                } else {
                    depth
                }
            }
            Node::BBF(_, parameters) => {
                let mut depth = 0;
                for parameter in parameters {
                    depth = depth.max(referenced_depth(*parameter)?);
                }
                depth
            }
            Node::RuntimeCall { parameters, .. } => {
                let mut depth = 0;
                for parameter in parameters {
                    depth = depth.max(referenced_depth(*parameter)?);
                }
                depth
            }
        };
        depths.push(depth);
    }

    if division_count == 0 {
        return Ok(EvaluationPlan::default());
    }

    let layer_count = depths.iter().copied().max().unwrap_or(0) + 1;
    let mut regular = vec![Vec::new(); layer_count];
    let mut divisions = vec![Vec::new(); layer_count];
    for (index, (&depth, node)) in depths.iter().zip(nodes.iter()).enumerate() {
        if matches!(node, Node::Op(Operation::Div, _, _)) {
            divisions[depth].push(index);
        } else {
            regular[depth].push(index);
        }
    }

    let mut order = Vec::with_capacity(nodes.len());
    let mut division_batches = Vec::with_capacity(layer_count);
    for depth in 0..layer_count {
        if !divisions[depth].is_empty() {
            let start = order.len();
            order.extend_from_slice(&divisions[depth]);
            division_batches.push(start..order.len());
        }
        order.extend_from_slice(&regular[depth]);
    }
    debug_assert_eq!(order.len(), nodes.len());

    let mut renumber = vec![0; nodes.len()];
    for (new, &old) in order.iter().enumerate() {
        renumber[old] = new;
    }
    let mut reordered = order
        .into_iter()
        .map(|index| nodes[index].clone())
        .collect::<Vec<_>>();
    for node in &mut reordered {
        match node {
            Node::Op(_, left, right) => {
                *left = renumber[*left];
                *right = renumber[*right];
            }
            Node::BBF(_, parameters) => {
                for parameter in parameters {
                    *parameter = renumber[*parameter];
                }
            }
            Node::RuntimeCall { parameters, .. } => {
                for parameter in parameters {
                    *parameter = renumber[*parameter];
                }
            }
            Node::Input(_) | Node::Constant(_) | Node::MontConstant(_) => {}
        }
    }
    for output in outputs {
        if *output >= renumber.len() {
            bail!("graph output node {output} is out of bounds");
        }
        *output = renumber[*output];
    }
    *nodes = reordered;
    assert_valid(nodes);

    Ok(EvaluationPlan { division_batches })
}

fn cmp_balanced(a: U256, b: U256) -> Ordering {
    match (a > M.shr(1), b > M.shr(1)) {
        (false, true) => Ordering::Greater,
        (true, false) => Ordering::Less,
        (false, false) => a.cmp(&b),
        (true, true) => {
            // both negative: compare reversed
            let ma = M - a;
            let mb = M - b;
            mb.cmp(&ma)
        }
    }
}

impl Operation {
    pub fn eval(&self, a: U256, b: U256) -> U256 {
        let a = a % M;
        let b = b % M;
        use Operation::*;
        match self {
            Add => a.add_mod(b, M),
            Sub => a.add_mod(M - b, M),
            Mul => a.mul_mod(b, M),
            Eq => U256::from(a == b),
            Neq => U256::from(a != b),
            Lt => U256::from(cmp_balanced(a, b).is_lt()),
            Gt => U256::from(cmp_balanced(a, b).is_gt()),
            Leq => U256::from(cmp_balanced(a, b).is_le()),
            Geq => U256::from(cmp_balanced(a, b).is_ge()),
            Lor => U256::from(a != U256::ZERO || b != U256::ZERO),
            Shl => compute_shl(a, b),
            Shr => compute_shr(a, b),
            Bor => a.bitor(b) % M,
            Band => a.bitand(b) % M,
            Bxor => a.bitxor(b) % M,
            Bnot => (bit_mask() ^ a) % M,
            Lnot => U256::from(a == U256::ZERO),
            Land => U256::from(a != U256::ZERO && b != U256::ZERO),
            Neg => (M - a) % M,
            Inv => a.inv_mod(M).unwrap(),
            Div => a.mul_mod(b.inv_mod(M).unwrap(), M),
            SafeDiv => b
                .inv_mod(M)
                .map(|inverse| a.mul_mod(inverse, M))
                .unwrap_or(U256::ZERO),
            Mod => a.reduce_mod(b),
            Pow => a.pow_mod(b, M),
            IDiv => a / b,
            _ => unimplemented!("operator {:?} not implemented", self),
        }
    }

    pub fn eval_fr(&self, a: Fr, b: Fr) -> Fr {
        use Operation::*;
        match self {
            Add => a + b,
            Sub => a - b,
            Mul => a * b,
            Eq => (a == b).into(),
            Neg => -a,
            Div => a / b,
            SafeDiv => {
                if b == Fr::from(0_u64) {
                    Fr::from(0_u64)
                } else {
                    a / b
                }
            }
            IDiv => {
                let a: BigUint = a.into();
                let b: BigUint = b.into();
                Fr::from(a / b)
            }
            Mod => {
                let a: BigUint = a.into();
                let b: BigUint = b.into();
                Fr::from(a % b)
            }
            _ => {
                let a: U256 = a.into();
                let b: U256 = b.into();
                Fr::new(self.eval(a, b).into())
            }
        }
    }
}

fn compute_shl(a: U256, b: U256) -> U256 {
    if b > M.shr(1) {
        shift_right(a, M - b)
    } else {
        shift_left(a, b)
    }
}

fn compute_shr(a: U256, b: U256) -> U256 {
    if b > M.shr(1) {
        shift_left(a, M - b)
    } else {
        shift_right(a, b)
    }
}

fn bit_mask() -> U256 {
    (U256::ONE << M.bit_len()) - U256::ONE
}

fn shift_left(a: U256, amount: U256) -> U256 {
    if amount >= uint!(254) {
        U256::ZERO
    } else {
        ((a << amount.to::<usize>()) & bit_mask()) % M
    }
}

fn shift_right(a: U256, amount: U256) -> U256 {
    if amount >= uint!(254) {
        U256::ZERO
    } else {
        (a >> amount.to::<usize>()) % M
    }
}

/// All references must be backwards.
fn assert_valid(nodes: &[Node]) {
    for (i, node) in nodes.iter().enumerate() {
        match node {
            Node::Op(_, a, b) => {
                assert!(*a < i);
                assert!(*b < i);
            }
            Node::BBF(_, parameters) | Node::RuntimeCall { parameters, .. } => {
                assert!(parameters.iter().all(|parameter| *parameter < i));
            }
            Node::Input(_) | Node::Constant(_) | Node::MontConstant(_) => {}
        }
    }
}

pub fn optimize(nodes: &mut Vec<Node>, outputs: &mut [usize]) {
    tree_shake(nodes, outputs);
    propagate(nodes);
    value_numbering(nodes, outputs);
    constants(nodes);
    tree_shake(nodes, outputs);
    montgomery_form(nodes);
}

fn strip_suffix_number(s: String) -> String {
    if let Some(pos) = s.rfind('_') {
        let (prefix, suffix) = s.split_at(pos);
        if suffix[1..].chars().all(|c| c.is_ascii_digit()) {
            return prefix.to_string();
        }
    }
    s
}

pub fn evaluate(
    nodes: &[Node],
    inputs: &[U256],
    outputs: &[usize],
    bbfs: Option<&HashMap<String, BlackBoxFunction>>,
) -> eyre::Result<Vec<U256>> {
    assert_valid(nodes);
    evaluate_with_plan(nodes, inputs, outputs, bbfs, &EvaluationPlan::default())
}

pub(crate) fn evaluate_with_plan(
    nodes: &[Node],
    inputs: &[U256],
    outputs: &[usize],
    bbfs: Option<&HashMap<String, BlackBoxFunction>>,
    plan: &EvaluationPlan,
) -> eyre::Result<Vec<U256>> {
    // Evaluate the graph.
    let mut values = Vec::with_capacity(nodes.len());
    let mut inverses = Vec::new();
    let mut inversion_scratch = Vec::new();
    let mut batches = plan.division_batches.iter().peekable();
    let mut index = 0;
    while index < nodes.len() {
        if batches.peek().is_some_and(|batch| batch.start == index) {
            let batch = batches.next().unwrap().clone();
            inverses.clear();
            for node in &nodes[batch.clone()] {
                let Node::Op(Operation::Div, _, divisor) = node else {
                    unreachable!("division batch contains a non-division node")
                };
                inverses.push(values[*divisor]);
            }
            batch_inversion_u256(&mut inverses, &mut inversion_scratch);
            for (node, inverse) in nodes[batch.clone()].iter().zip(&inverses) {
                let Node::Op(Operation::Div, numerator, _) = node else {
                    unreachable!("division batch contains a non-division node")
                };
                values.push(values[*numerator] * inverse);
            }
            index = batch.end;
            continue;
        }

        let node = &nodes[index];
        let value = match node {
            Node::Constant(c) => Fr::new(c.into()),
            Node::MontConstant(c) => *c,
            Node::Input(i) => {
                if *i < inputs.len() {
                    Fr::new(inputs[*i].into())
                } else {
                    Fr::new(U256::MAX.into())
                }
            }
            Node::Op(op, a, b) => op.eval_fr(values[*a], values[*b]),
            Node::BBF(name, params) => {
                if let Some(bbfs) = bbfs {
                    let params = params.iter().map(|i| values[*i]).collect::<Vec<_>>();
                    let name = strip_suffix_number(name.clone());
                    if let Some(bbf) = bbfs.get(&name) {
                        bbf(&params)
                    } else {
                        bail!("black box function {:?} not found", name);
                    }
                } else {
                    bail!("no black box functions provided");
                }
            }
            Node::RuntimeCall { .. } => {
                bail!("runtime Circom calls require their serialized function table")
            }
        };
        values.push(value);
        index += 1;
    }

    // Convert from Montgomery form and return the outputs.
    let mut out = vec![U256::ZERO; outputs.len()];
    for i in 0..outputs.len() {
        out[i] = values[outputs[i]].into();
    }

    Ok(out)
}

/// Invert a set of non-zero field elements with a single modular inversion.
///
/// Multiplication remains in Montgomery form. Only the accumulated product takes the round trip
/// through canonical `U256`, where `ruint`'s modular inverse is substantially faster than the
/// generic field inversion. `scratch` is retained by the caller and reused across division batches.
pub(crate) fn batch_inversion_u256(values: &mut [Fr], scratch: &mut Vec<Fr>) {
    scratch.clear();
    scratch.reserve(values.len());

    let mut product = Fr::from(1_u64);
    for &value in values.iter() {
        assert!(value != Fr::from(0_u64), "attempt to divide by zero");
        scratch.push(product);
        product *= value;
    }

    if values.is_empty() {
        return;
    }

    let product: U256 = product.into();
    let product_inverse = product
        .inv_mod(M)
        .expect("a product of non-zero field elements must be invertible");
    let mut inverse = Fr::new(product_inverse.into());

    for (value, prefix) in values.iter_mut().zip(scratch.iter()).rev() {
        let original = *value;
        *value = inverse * prefix;
        inverse *= original;
    }
}

/// Constant propagation
pub fn propagate(nodes: &mut [Node]) {
    assert_valid(nodes);
    let mut constants = 0_usize;
    for i in 0..nodes.len() {
        if let Node::Op(op, a, b) = nodes[i] {
            if let (Node::Constant(va), Node::Constant(vb)) = (nodes[a].clone(), nodes[b].clone()) {
                nodes[i] = Node::Constant(op.eval(va, vb));
                constants += 1;
            } else if a == b {
                // Not constant but equal
                use Operation::*;
                if let Some(c) = match op {
                    Eq | Leq | Geq => Some(true),
                    Neq | Lt | Gt => Some(false),
                    _ => None,
                } {
                    nodes[i] = Node::Constant(U256::from(c));
                    constants += 1;
                }
            }
        }
    }

    eprintln!("Propagated {constants} constants");
}

/// Remove unused nodes
pub fn tree_shake(nodes: &mut Vec<Node>, outputs: &mut [usize]) {
    assert_valid(nodes);

    // Mark all nodes that are used.
    let mut used = vec![false; nodes.len()];
    for &i in outputs.iter() {
        used[i] = true;
    }

    // Work backwards from end as all references are backwards.
    for i in (0..nodes.len()).rev() {
        if used[i] {
            if let Node::Op(_, a, b) = nodes[i] {
                used[a] = true;
                used[b] = true;
            }
            if let Node::BBF(_, params) = &nodes[i] {
                for &param in params.iter() {
                    used[param] = true;
                }
            }
            if let Node::RuntimeCall { parameters, .. } = &nodes[i] {
                for &parameter in parameters {
                    used[parameter] = true;
                }
            }
        }
    }

    // Remove unused nodes
    let n = nodes.len();
    let mut retain = used.iter();
    nodes.retain(|_| *retain.next().unwrap());
    let removed = n - nodes.len();

    // Renumber references.
    let mut renumber = vec![None; n];
    let mut index = 0;
    for (i, &used) in used.iter().enumerate() {
        if used {
            renumber[i] = Some(index);
            index += 1;
        }
    }
    assert_eq!(index, nodes.len());
    for (&used, renumber) in used.iter().zip(renumber.iter()) {
        assert_eq!(used, renumber.is_some());
    }

    // Renumber references.
    for node in nodes.iter_mut() {
        if let Node::Op(_, a, b) = node {
            *a = renumber[*a].unwrap();
            *b = renumber[*b].unwrap();
        }
        if let Node::BBF(_, params) = node {
            for param in params.iter_mut() {
                *param = renumber[*param].unwrap();
            }
        }
        if let Node::RuntimeCall { parameters, .. } = node {
            for parameter in parameters {
                *parameter = renumber[*parameter].unwrap();
            }
        }
    }
    for output in outputs.iter_mut() {
        *output = renumber[*output].unwrap();
    }

    eprintln!("Removed {removed} unused nodes");
}

/// Randomly evaluate the graph
fn random_eval(nodes: &mut [Node]) -> Vec<U256> {
    let mut rng = rand::thread_rng();
    let mut values = Vec::with_capacity(nodes.len());
    let mut inputs = HashMap::new();
    let mut prfs = HashMap::new();
    for node in nodes.iter() {
        use Operation::*;
        let value = match node {
            Node::BBF(_, _) | Node::RuntimeCall { .. } => rng.gen::<U256>() % M,
            // Constants evaluate to themselves
            Node::Constant(c) => *c,

            Node::MontConstant(_) => unimplemented!("should not be used"),

            // Algebraic Ops are evaluated directly
            // Since the field is large, by Swartz-Zippel if
            // two values are the same then they are likely algebraically equal.
            Node::Op(op @ (Add | Sub | Mul | Neg), a, b) => op.eval(values[*a], values[*b]),

            // Input and non-algebraic ops are random functions
            // TODO: https://github.com/recmo/uint/issues/95 and use .gen_range(..M)
            Node::Input(i) => *inputs.entry(*i).or_insert_with(|| rng.gen::<U256>() % M),
            Node::Op(op, a, b) => *prfs
                .entry((*op, values[*a], values[*b]))
                .or_insert_with(|| rng.gen::<U256>() % M),
        };
        values.push(value);
    }
    values
}

/// Value numbering
pub fn value_numbering(nodes: &mut [Node], outputs: &mut [usize]) {
    assert_valid(nodes);

    // Evaluate the graph in random field elements.
    let values = random_eval(nodes);

    // Find all nodes with the same value.
    let mut value_map = HashMap::new();
    for (i, &value) in values.iter().enumerate() {
        value_map.entry(value).or_insert_with(Vec::new).push(i);
    }

    // For nodes that are the same, pick the first index.
    let mut renumber = Vec::with_capacity(nodes.len());
    for value in values {
        renumber.push(value_map[&value][0]);
    }

    // Renumber references.
    for node in nodes.iter_mut() {
        if let Node::Op(_, a, b) = node {
            *a = renumber[*a];
            *b = renumber[*b];
        }

        if let Node::BBF(_, params) = node {
            for p in params.iter_mut() {
                *p = renumber[*p];
            }
        }
        if let Node::RuntimeCall { parameters, .. } = node {
            for parameter in parameters {
                *parameter = renumber[*parameter];
            }
        }
    }
    for output in outputs.iter_mut() {
        *output = renumber[*output];
    }

    eprintln!("Global value numbering applied");
}

/// Probabilistic constant determination
pub fn constants(nodes: &mut [Node]) {
    assert_valid(nodes);

    // Evaluate the graph in random field elements.
    let values_a = random_eval(nodes);
    let values_b = random_eval(nodes);

    // Find all nodes with the same value.
    let mut constants = 0;
    for i in 0..nodes.len() {
        if let Node::Constant(_) = nodes[i] {
            continue;
        }
        if values_a[i] == values_b[i] {
            nodes[i] = Node::Constant(values_a[i]);
            constants += 1;
        }
    }
    eprintln!("Found {constants} constants");
}

/// Convert to Montgomery form
pub fn montgomery_form(nodes: &mut [Node]) {
    for node in nodes.iter_mut() {
        use Node::*;
        match node {
            Constant(c) => *node = MontConstant(Fr::new((*c).into())),
            MontConstant(..) => (),
            Input(..) => (),
            Op(..) => (),
            BBF(..) => (),
            RuntimeCall { .. } => (),
        }
    }
    eprintln!("Converted to Montgomery form");
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::batch_inversion;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn bitwise_complement_uses_the_field_bit_width() {
        assert_eq!(Operation::Bnot.eval(U256::ZERO, U256::ZERO), bit_mask() % M);
        assert_eq!(Operation::Bnot.eval(bit_mask(), U256::ZERO), U256::ZERO);
    }

    #[test]
    fn shifts_follow_circoms_signed_field_semantics() {
        let negative_one = M - U256::ONE;
        assert_eq!(
            Operation::Shl.eval(uint!(8_U256), U256::ONE),
            uint!(16_U256)
        );
        assert_eq!(Operation::Shr.eval(uint!(8_U256), U256::ONE), uint!(4_U256));
        assert_eq!(
            Operation::Shl.eval(uint!(8_U256), negative_one),
            uint!(4_U256)
        );
        assert_eq!(
            Operation::Shr.eval(uint!(8_U256), negative_one),
            uint!(16_U256)
        );
        assert_eq!(
            Operation::Shl.eval(uint!(8_U256), uint!(254_U256)),
            U256::ZERO
        );
        assert_eq!(
            Operation::Shr.eval(uint!(8_U256), uint!(254_U256)),
            U256::ZERO
        );
    }

    #[test]
    fn independent_divisions_are_batched_without_changing_results() {
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
        ];
        let outputs = vec![5, 6, 7, 8];
        let inputs = vec![U256::from(6), U256::from(5), U256::from(2)];
        let expected = evaluate(&nodes, &inputs, &outputs, None).unwrap();

        let mut reordered = nodes;
        let mut reordered_outputs = outputs;
        let plan = prepare_evaluation(&mut reordered, &mut reordered_outputs).unwrap();
        assert_eq!(plan.division_batches.len(), 2);
        assert_eq!(plan.division_batches[0].len(), 2);
        assert_eq!(plan.division_batches[1].len(), 1);

        let actual =
            evaluate_with_plan(&reordered, &inputs, &reordered_outputs, None, &plan).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn u256_batch_inversion_matches_ark_for_varying_batch_sizes() {
        let mut rng = StdRng::seed_from_u64(0x7869_3262_6174_6368);
        let mut scratch = Vec::new();

        for size in [0, 1, 2, 3, 7, 32, 127, 256] {
            let mut actual = (0..size)
                .map(|_| {
                    let mut value = rng.gen::<U256>() % M;
                    if value == U256::ZERO {
                        value = U256::ONE;
                    }
                    Fr::new(value.into())
                })
                .collect::<Vec<_>>();
            let mut expected = actual.clone();

            batch_inversion(&mut expected);
            batch_inversion_u256(&mut actual, &mut scratch);

            assert_eq!(actual, expected, "batch size {size}");
            assert_eq!(scratch.len(), size);
        }
    }

    #[test]
    #[should_panic(expected = "attempt to divide by zero")]
    fn u256_batch_inversion_rejects_zero() {
        let mut values = [Fr::from(3_u64), Fr::from(0_u64), Fr::from(7_u64)];
        batch_inversion_u256(&mut values, &mut Vec::new());
    }
}
