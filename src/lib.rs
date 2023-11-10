mod field;
mod graph;

pub mod generate;

use std::collections::HashMap;

use ruint::aliases::U256;
use serde::{Deserialize, Serialize};

use crate::graph::Node;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct HashSignalInfo {
    pub hash: u64,
    pub signalid: u64,
    pub signalsize: u64,
}

fn fnv1a(s: &str) -> u64 {
    let mut hash: u64 = 0xCBF29CE484222325;
    for c in s.bytes() {
        hash ^= c as u64;
        hash = hash.wrapping_mul(0x100000001B3);
    }
    hash
}

fn set_input_signal_eval(
    input_hashmap: Vec<HashSignalInfo>,
    signal_values: &mut Vec<U256>,
    h: u64,
    i: u64,
    val: U256,
) {
    let pos = input_hashmap.iter().position(|x| x.hash == h).unwrap();
    let si = (input_hashmap[pos].signalid + i) as usize;
    signal_values[si] = val;
}

/// Calculate witness based on serialized graph and inputs
pub fn calculate_witness(
    input_list: HashMap<String, Vec<U256>>,
    graph_bytes: &[u8],
) -> eyre::Result<Vec<U256>> {
    let (nodes, signals, input_mapping): (Vec<Node>, Vec<usize>, Vec<HashSignalInfo>) =
        postcard::from_bytes(graph_bytes)?;

    // Calculate number of inputs from graph
    let mut start = false;
    let mut max_index = 0usize;
    for &node in nodes.iter() {
        if let Node::Input(i) = node {
            if i > max_index {
                max_index = i;
            }
            start = true
        } else if start {
            break;
        }
    }

    // Prepare inputs
    let mut inputs = vec![U256::ZERO; max_index + 1];
    inputs[0] = U256::from(1);

    // Set input values from JSON
    for (key, value) in input_list {
        let h = fnv1a(key.as_str());
        for (idx, item) in value.into_iter().enumerate() {
            set_input_signal_eval(input_mapping.clone(), &mut inputs, h, idx as u64, item);
        }
    }

    // Calculate witness
    let witness = graph::evaluate(&nodes, &inputs, &signals);

    Ok(witness)
}
