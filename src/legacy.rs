//! Decoder for the unversioned graph format emitted by circom-witness-rs v0.3.0 and earlier.
//!
//! Postcard encodes enum variants by their ordinal. Keep these definitions frozen instead of
//! deserializing old artifacts directly into the current, extensible graph enums.

use ark_bn254::Fr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use eyre::Context as _;
use ruint::aliases::U256;
use serde::{Deserialize, Serialize};

use crate::{
    graph::{Node, Operation},
    HashSignalInfo,
};

fn ark_se<S, A: CanonicalSerialize>(value: &A, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let mut bytes = Vec::new();
    value
        .serialize_with_mode(&mut bytes, Compress::Yes)
        .map_err(serde::ser::Error::custom)?;
    serializer.serialize_bytes(&bytes)
}

fn ark_de<'de, D, A: CanonicalDeserialize>(deserializer: D) -> Result<A, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let bytes = Vec::<u8>::deserialize(deserializer)?;
    A::deserialize_with_mode(bytes.as_slice(), Compress::Yes, Validate::Yes)
        .map_err(serde::de::Error::custom)
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
enum LegacyOperation {
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
}

impl From<LegacyOperation> for Operation {
    fn from(operation: LegacyOperation) -> Self {
        match operation {
            LegacyOperation::Mul => Self::Mul,
            LegacyOperation::MMul => Self::MMul,
            LegacyOperation::Add => Self::Add,
            LegacyOperation::Sub => Self::Sub,
            LegacyOperation::Eq => Self::Eq,
            LegacyOperation::Neq => Self::Neq,
            LegacyOperation::Lt => Self::Lt,
            LegacyOperation::Gt => Self::Gt,
            LegacyOperation::Leq => Self::Leq,
            LegacyOperation::Geq => Self::Geq,
            LegacyOperation::Lor => Self::Lor,
            LegacyOperation::Shl => Self::Shl,
            LegacyOperation::Shr => Self::Shr,
            LegacyOperation::Band => Self::Band,
            LegacyOperation::Neg => Self::Neg,
            LegacyOperation::Inv => Self::Inv,
            LegacyOperation::Div => Self::Div,
            LegacyOperation::Mod => Self::Mod,
            LegacyOperation::Pow => Self::Pow,
            LegacyOperation::Land => Self::Land,
            LegacyOperation::IDiv => Self::IDiv,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::upper_case_acronyms)]
enum LegacyNode {
    Input(usize),
    Constant(U256),
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    MontConstant(Fr),
    Op(LegacyOperation, usize, usize),
    BBF(String, Vec<usize>),
}

impl From<LegacyNode> for Node {
    fn from(node: LegacyNode) -> Self {
        match node {
            LegacyNode::Input(index) => Self::Input(index),
            LegacyNode::Constant(value) => Self::Constant(value),
            LegacyNode::MontConstant(value) => Self::MontConstant(value),
            LegacyNode::Op(operation, left, right) => Self::Op(operation.into(), left, right),
            LegacyNode::BBF(name, parameters) => Self::BBF(name, parameters),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct LegacyHashSignalInfo {
    hash: u64,
    signalid: u64,
    signalsize: u64,
}

impl From<LegacyHashSignalInfo> for HashSignalInfo {
    fn from(info: LegacyHashSignalInfo) -> Self {
        Self {
            hash: info.hash,
            signalid: info.signalid,
            signalsize: info.signalsize,
        }
    }
}

pub(crate) fn decode(bytes: &[u8]) -> eyre::Result<(Vec<Node>, Vec<usize>, Vec<HashSignalInfo>)> {
    let (nodes, signals, input_mapping): (Vec<LegacyNode>, Vec<usize>, Vec<LegacyHashSignalInfo>) =
        postcard::from_bytes(bytes).wrap_err("failed to decode v0.3.0-or-earlier witness graph")?;

    Ok((
        nodes.into_iter().map(Node::from).collect(),
        signals,
        input_mapping
            .into_iter()
            .map(HashSignalInfo::from)
            .collect(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{get_inputs_size, init_graph};

    #[test]
    fn v0_3_schema_converts_every_node_and_operation_variant() {
        let operations = [
            LegacyOperation::Mul,
            LegacyOperation::MMul,
            LegacyOperation::Add,
            LegacyOperation::Sub,
            LegacyOperation::Eq,
            LegacyOperation::Neq,
            LegacyOperation::Lt,
            LegacyOperation::Gt,
            LegacyOperation::Leq,
            LegacyOperation::Geq,
            LegacyOperation::Lor,
            LegacyOperation::Shl,
            LegacyOperation::Shr,
            LegacyOperation::Band,
            LegacyOperation::Neg,
            LegacyOperation::Inv,
            LegacyOperation::Div,
            LegacyOperation::Mod,
            LegacyOperation::Pow,
            LegacyOperation::Land,
            LegacyOperation::IDiv,
        ];
        let mut legacy_nodes = vec![
            LegacyNode::Input(0),
            LegacyNode::Constant(U256::from(2_u64)),
            LegacyNode::MontConstant(Fr::from(3_u64)),
        ];
        legacy_nodes.extend(
            operations
                .into_iter()
                .map(|operation| LegacyNode::Op(operation, 0, 1)),
        );
        legacy_nodes.push(LegacyNode::BBF("legacy_0".to_owned(), vec![0, 1]));
        let signals = vec![2, legacy_nodes.len() - 1];
        let mapping = vec![LegacyHashSignalInfo {
            hash: 42,
            signalid: 0,
            signalsize: 1,
        }];
        let bytes = postcard::to_stdvec(&(&legacy_nodes, &signals, &mapping)).unwrap();

        let (nodes, decoded_signals, decoded_mapping) = decode(&bytes).unwrap();

        assert_eq!(decoded_signals, signals);
        assert_eq!(nodes.len(), legacy_nodes.len());
        assert_eq!(decoded_mapping[0].hash, 42);
        for (index, operation) in operations.into_iter().enumerate() {
            assert_eq!(nodes[index + 3], Node::Op(operation.into(), 0, 1));
        }

        let graph = init_graph(&bytes).unwrap();
        assert_eq!(get_inputs_size(&graph), 1);
        assert_eq!(graph.nodes().len(), legacy_nodes.len());
    }

    #[test]
    fn v0_3_graph_evaluates_with_the_current_runtime() {
        // Emitted by the circom-witness-rs v0.3.0 tag. SHA-256:
        // 8fb29f7c309ad8ca606c906592d343b6f5fdc2658579c88c318a9053bc423b19
        const GRAPH: &[u8] = &[
            0x07, 0x00, 0x00, 0x00, 0x01, 0x01, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x02, 0x20, 0x0b,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x03, 0x02, 0x00, 0x01, 0x03, 0x00, 0x04, 0x02, 0x03, 0x02, 0x05,
            0x03, 0x01, 0x06, 0x01, 0x2a, 0x01, 0x01,
        ];

        let graph = init_graph(GRAPH).unwrap();

        assert_eq!(
            graph
                .evaluate(&[U256::from(2_u64), U256::from(3_u64)], None)
                .unwrap(),
            vec![U256::from(46_u64)]
        );
    }
}
