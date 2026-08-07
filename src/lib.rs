pub mod graph;

#[cfg(feature = "build-witness")]
pub mod generate;

use std::{collections::HashMap, sync::Arc};

use ark_bn254::Fr;
use eyre::{eyre, Context as _};
use ruint::{aliases::U256, uint};
use serde::{Deserialize, Serialize};

use crate::graph::Node;

pub type BlackBoxFunction = Arc<dyn Fn(&[Fr]) -> Fr + Send + Sync + 'static>;

pub const M: U256 =
    uint!(21888242871839275222246405745257275088548364400416034343698204186575808495617_U256);

const GRAPH_HEADER: &[u8; 8] = b"CWGR\x01DZ\0";
const GRAPH_MAGIC: &[u8; 4] = b"CWGR";
#[cfg(any(feature = "build-witness", test))]
const GRAPH_COMPRESSION_LEVEL: i32 = 19;

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashSignalInfo {
    pub hash: u64,
    pub signalid: u64,
    pub signalsize: u64,
}

#[derive(Clone)]
pub struct Graph {
    pub nodes: Vec<Node>,
    pub signals: Vec<usize>,
    pub input_mapping: Vec<HashSignalInfo>,
    evaluation_plan: graph::EvaluationPlan,
}

impl Graph {
    /// Evaluates a graph using an already populated positional input buffer.
    pub fn evaluate(
        &self,
        inputs: &[U256],
        bbfs: Option<&HashMap<String, BlackBoxFunction>>,
    ) -> eyre::Result<Vec<U256>> {
        graph::evaluate_with_plan(
            &self.nodes,
            inputs,
            &self.signals,
            bbfs,
            &self.evaluation_plan,
        )
    }
}

#[cfg(any(feature = "build-witness", test))]
fn encode_backward_reference(node: usize, reference: usize) -> eyre::Result<usize> {
    node.checked_sub(reference)
        .and_then(|distance| distance.checked_sub(1))
        .ok_or_else(|| eyre!("graph node {node} does not reference an earlier node {reference}"))
}

fn decode_backward_reference(node: usize, distance: usize) -> eyre::Result<usize> {
    node.checked_sub(
        distance
            .checked_add(1)
            .ok_or_else(|| eyre!("graph reference distance overflowed"))?,
    )
    .ok_or_else(|| eyre!("graph reference distance {distance} is invalid at node {node}"))
}

#[cfg(any(feature = "build-witness", test))]
fn encode_output_delta(output: usize, previous: usize) -> eyre::Result<usize> {
    if output >= previous {
        (output - previous)
            .checked_mul(2)
            .ok_or_else(|| eyre!("graph output delta overflowed"))
    } else {
        (previous - output)
            .checked_mul(2)
            .and_then(|delta| delta.checked_sub(1))
            .ok_or_else(|| eyre!("graph output delta overflowed"))
    }
}

fn decode_output_delta(encoded: usize, previous: usize) -> eyre::Result<usize> {
    if encoded & 1 == 0 {
        previous
            .checked_add(encoded / 2)
            .ok_or_else(|| eyre!("graph output delta overflowed"))
    } else {
        previous
            .checked_sub(encoded / 2 + 1)
            .ok_or_else(|| eyre!("graph output delta is invalid"))
    }
}

#[cfg(any(feature = "build-witness", test))]
pub(crate) fn serialize_graph(
    mut nodes: Vec<Node>,
    mut signals: Vec<usize>,
    input_mapping: Vec<HashSignalInfo>,
) -> eyre::Result<Vec<u8>> {
    for (index, node) in nodes.iter_mut().enumerate() {
        match node {
            Node::Op(_, left, right) => {
                *left = encode_backward_reference(index, *left)?;
                *right = encode_backward_reference(index, *right)?;
            }
            Node::BBF(_, parameters) => {
                for parameter in parameters {
                    *parameter = encode_backward_reference(index, *parameter)?;
                }
            }
            Node::Input(_) | Node::Constant(_) | Node::MontConstant(_) => {}
        }
    }

    let mut previous = 0;
    for output in &mut signals {
        let absolute = *output;
        *output = encode_output_delta(absolute, previous)?;
        previous = absolute;
    }

    let postcard = postcard::to_stdvec(&(&nodes, &signals, &input_mapping))?;
    let compressed = zstd::stream::encode_all(postcard.as_slice(), GRAPH_COMPRESSION_LEVEL)
        .wrap_err("failed to compress witness graph")?;
    let mut encoded = Vec::with_capacity(GRAPH_HEADER.len() + compressed.len());
    encoded.extend_from_slice(GRAPH_HEADER);
    encoded.extend_from_slice(&compressed);
    Ok(encoded)
}

fn restore_absolute_references(nodes: &mut [Node], signals: &mut [usize]) -> eyre::Result<()> {
    for (index, node) in nodes.iter_mut().enumerate() {
        match node {
            Node::Op(_, left, right) => {
                *left = decode_backward_reference(index, *left)?;
                *right = decode_backward_reference(index, *right)?;
            }
            Node::BBF(_, parameters) => {
                for parameter in parameters {
                    *parameter = decode_backward_reference(index, *parameter)?;
                }
            }
            Node::Input(_) | Node::Constant(_) | Node::MontConstant(_) => {}
        }
    }

    let mut previous = 0;
    for output in signals {
        *output = decode_output_delta(*output, previous)?;
        if *output >= nodes.len() {
            return Err(eyre!("graph output node {} is out of bounds", *output));
        }
        previous = *output;
    }
    Ok(())
}

fn fnv1a(s: &str) -> u64 {
    let mut hash: u64 = 0xCBF29CE484222325;
    for c in s.bytes() {
        hash ^= c as u64;
        hash = hash.wrapping_mul(0x100000001B3);
    }
    hash
}

/// Loads the graph from bytes
pub fn init_graph(graph_bytes: &[u8]) -> eyre::Result<Graph> {
    let compressed = if graph_bytes.starts_with(GRAPH_MAGIC) {
        let header = graph_bytes
            .get(..GRAPH_HEADER.len())
            .ok_or_else(|| eyre!("witness graph header is truncated"))?;
        if header != GRAPH_HEADER {
            return Err(eyre!("unsupported witness graph format"));
        }
        Some(&graph_bytes[GRAPH_HEADER.len()..])
    } else {
        None
    };
    let postcard;
    let graph_bytes = if let Some(compressed) = compressed {
        postcard =
            zstd::stream::decode_all(compressed).wrap_err("failed to decompress witness graph")?;
        postcard.as_slice()
    } else {
        graph_bytes
    };
    let (mut nodes, mut signals, input_mapping): (Vec<Node>, Vec<usize>, Vec<HashSignalInfo>) =
        postcard::from_bytes(graph_bytes)?;

    if compressed.is_some() {
        restore_absolute_references(&mut nodes, &mut signals)?;
    }

    let evaluation_plan = graph::prepare_evaluation(&mut nodes, &mut signals)?;

    Ok(Graph {
        nodes,
        signals,
        input_mapping,
        evaluation_plan,
    })
}

/// Calculates the number of needed inputs
pub fn get_inputs_size(graph: &Graph) -> usize {
    let mut start = false;
    let mut max_index = 0usize;
    for node in graph.nodes.iter() {
        if let Node::Input(i) = node {
            if *i > max_index {
                max_index = *i;
            }
            start = true
        } else if start {
            break;
        }
    }
    max_index + 1
}

/// Allocates inputs vec with position 0 set to 1
pub fn get_inputs_buffer(size: usize) -> Vec<U256> {
    let mut inputs = vec![U256::ZERO; size];
    inputs[0] = U256::from(1);
    inputs
}

/// Calculates the position of the given signal in the inputs buffer
pub fn get_input_mapping(input_list: &Vec<String>, graph: &Graph) -> HashMap<String, usize> {
    let mut input_mapping = HashMap::new();
    for key in input_list {
        let h = fnv1a(key);
        let pos = graph
            .input_mapping
            .iter()
            .position(|x| x.hash == h)
            .unwrap();
        let si = (graph.input_mapping[pos].signalid) as usize;
        input_mapping.insert(key.to_string(), si);
    }
    input_mapping
}

/// Sets all provided inputs given the mapping and inputs buffer
pub fn populate_inputs(
    input_list: &HashMap<String, Vec<U256>>,
    input_mapping: &HashMap<String, usize>,
    input_buffer: &mut [U256],
) {
    for (key, value) in input_list {
        let start = input_mapping[key];
        let end = start + value.len();
        input_buffer[start..end].copy_from_slice(value);
    }
}

/// Calculate witness based on serialized graph and inputs
pub fn calculate_witness(
    input_list: HashMap<String, Vec<U256>>,
    graph: &Graph,
    bbfs: Option<&HashMap<String, BlackBoxFunction>>,
) -> eyre::Result<Vec<U256>> {
    let mut inputs_buffer = get_inputs_buffer(get_inputs_size(graph));
    let input_mapping = get_input_mapping(&input_list.keys().cloned().collect(), graph);
    populate_inputs(&input_list, &input_mapping, &mut inputs_buffer);
    graph.evaluate(&inputs_buffer, bbfs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::Operation;

    fn graph_parts() -> (Vec<Node>, Vec<usize>, Vec<HashSignalInfo>) {
        let nodes = vec![
            Node::Input(0),
            Node::Input(1),
            Node::Op(Operation::Add, 0, 1),
            Node::Op(Operation::Mul, 2, 0),
            Node::BBF("bbf_test_0".to_owned(), vec![3, 1]),
        ];
        let signals = vec![4, 2, 3];
        let input_mapping = vec![HashSignalInfo {
            hash: 42,
            signalid: 1,
            signalsize: 1,
        }];
        (nodes, signals, input_mapping)
    }

    #[test]
    fn compressed_delta_graph_round_trips() {
        let (nodes, signals, input_mapping) = graph_parts();
        let encoded =
            serialize_graph(nodes.clone(), signals.clone(), input_mapping.clone()).unwrap();
        assert!(encoded.starts_with(GRAPH_HEADER));

        let graph = init_graph(&encoded).unwrap();
        assert_eq!(graph.nodes, nodes);
        assert_eq!(graph.signals, signals);
        assert_eq!(graph.input_mapping, input_mapping);
    }

    #[test]
    fn legacy_postcard_graphs_remain_supported() {
        let (nodes, signals, input_mapping) = graph_parts();
        let encoded = postcard::to_stdvec(&(&nodes, &signals, &input_mapping)).unwrap();

        let graph = init_graph(&encoded).unwrap();
        assert_eq!(graph.nodes, nodes);
        assert_eq!(graph.signals, signals);
        assert_eq!(graph.input_mapping, input_mapping);
    }

    #[test]
    fn unknown_graph_versions_are_rejected() {
        let error = init_graph(b"CWGR\x02DZ\0payload").err().unwrap();
        assert!(error
            .to_string()
            .contains("unsupported witness graph format"));
    }
}
