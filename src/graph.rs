use std::collections::HashMap;

use crate::field::M;
use rand::Rng;
use ruint::aliases::U256;

#[derive(Hash, PartialEq, Eq, Debug, Clone, Copy)]
pub enum Operation {
    Mul,
    Add,
    Sub,
    Eq,
    Neq,
    Lt,
    Gt,
    Leq,
    Geq,
    Lor,
}

#[derive(Debug, Clone, Copy)]
pub enum Node {
    Input(usize),
    Constant(U256),
    Op(Operation, usize, usize),
}

impl Operation {
    pub fn eval(&self, a: U256, b: U256) -> U256 {
        use Operation::*;
        match self {
            Add => a.add_mod(b, M),
            Sub => a.add_mod(M - b, M),
            Mul => a.mul_mod(b, M),
            Eq => U256::from(a == b),
            Neq => U256::from(a != b),
            Lt => U256::from(a < b),
            Gt => U256::from(a > b),
            Leq => U256::from(a <= b),
            Geq => U256::from(a >= b),
            Lor => U256::from(a != U256::ZERO || b != U256::ZERO),
        }
    }
}

/// All references must be backwards.
fn assert_valid(nodes: &[Node]) {
    for (i, &node) in nodes.iter().enumerate() {
        if let Node::Op(_, a, b) = node {
            assert!(a < i);
            assert!(b < i);
        }
    }
}

/// Constant propagation
pub fn propagate(nodes: &mut [Node]) {
    assert_valid(nodes);
    let mut constants = 0_usize;
    for i in 0..nodes.len() {
        if let Node::Op(op, a, b) = nodes[i] {
            let (a, b) = (a as usize, b as usize);
            if let (Node::Constant(va), Node::Constant(vb)) = (nodes[a], nodes[b]) {
                nodes[i] = Node::Constant(op.eval(va, vb));
                constants += 1;
            }
        }
    }

    eprintln!("Propagated {} constants", constants);
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
    }
    for output in outputs.iter_mut() {
        *output = renumber[*output].unwrap();
    }

    eprintln!("Removed {} unused nodes", removed);
}

/// Global value numbering
pub fn global_value(nodes: &mut Vec<Node>, outputs: &mut [usize]) {
    assert_valid(nodes);

    // Evaluate the graph in random field elements.
    let mut rng = rand::thread_rng();
    let mut values = Vec::with_capacity(nodes.len());
    let mut inputs = HashMap::new();
    let mut prfs = HashMap::new();
    for node in nodes.iter() {
        use Operation::*;
        let value = match node {
            // Constants evaluate to themselves
            Node::Constant(c) => *c,

            // Algebraic Ops are evaluated directly
            // Since the field is large, by Swartz-Zippel if
            // two values are the same then they are likely algebraically equal.
            Node::Op(op @ (Add | Sub | Mul), a, b) => op.eval(values[*a], values[*b]),

            // Input and non-algebraic ops are random functions
            // TODO: https://github.com/recmo/uint/issues/95 and use .gen_range(..M)
            // TODO: Eq and Neq can become constant iff values[*a] == values[*b]
            Node::Op(op, a, b) => *prfs
                .entry((*op, values[*a], values[*b]))
                .or_insert_with(|| rng.gen::<U256>() % M),
            Node::Input(i) => *inputs.entry(*i).or_insert_with(|| rng.gen::<U256>() % M),
        };
        values.push(value);
    }

    // Find all nodes with the same value.
    let mut value_map = HashMap::new();
    for (i, &value) in values.iter().enumerate() {
        value_map.entry(value).or_insert_with(Vec::new).push(i);
    }

    // For nodes that are the same, pick the first index.
    let mut renumber = Vec::with_capacity(nodes.len());
    for i in 0..nodes.len() {
        let value = values[i];
        let index = value_map[&value][0];
        renumber.push(index);
    }

    // Renumber references.
    for node in nodes.iter_mut() {
        if let Node::Op(_, a, b) = node {
            *a = renumber[*a];
            *b = renumber[*b];
        }
    }
    for output in outputs.iter_mut() {
        *output = renumber[*output];
    }

    eprintln!("Global value numbering applied");
}
