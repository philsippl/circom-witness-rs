pub mod custom;
pub mod graph;
pub mod profile;
mod program;
#[doc(hidden)]
pub mod runtime;

use std::{
    collections::HashMap,
    sync::{Arc, OnceLock},
};

use ark_bn254::Fr;
use eyre::{eyre, Context as _};
use ruint::{aliases::U256, uint};
use serde::{Deserialize, Serialize};

use crate::graph::Node;

pub type BlackBoxFunction = Arc<dyn Fn(&[Fr]) -> Fr + Send + Sync + 'static>;

pub const M: U256 =
    uint!(21888242871839275222246405745257275088548364400416034343698204186575808495617_U256);

const GRAPH_HEADER: &[u8; 8] = b"CWGR\x04PZ\0";
#[doc(hidden)]
pub const DEFAULT_GRAPH_COMPRESSION_LEVEL: i32 = 19;

#[doc(hidden)]
pub fn validate_graph_compression_level(compression_level: i32) -> eyre::Result<()> {
    let supported_levels = zstd::compression_level_range();
    if supported_levels.contains(&compression_level) {
        Ok(())
    } else {
        Err(eyre!(
            "zstd compression level {compression_level} is outside the supported range {}..={}",
            supported_levels.start(),
            supported_levels.end(),
        ))
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashSignalInfo {
    pub hash: u64,
    pub signalid: u64,
    pub signalsize: u64,
}

#[derive(Clone)]
pub struct Graph {
    // The program is the executable source of truth. Fused graphs construct the semantically
    // equivalent node view only if the compatibility accessors are actually used.
    compatibility: OnceLock<CompatibilityGraph>,
    pub input_mapping: Vec<HashSignalInfo>,
    program: program::Program,
}

/// Stateful evaluator for repeated witnesses from the same graph.
///
/// Black-box callbacks are resolved when this is constructed, and execution buffers are retained
/// between calls. The witness returned by [`WitnessEvaluator::evaluate`] remains valid only until
/// the next evaluation on this object.
pub struct WitnessEvaluator<'graph> {
    graph: &'graph Graph,
    black_boxes: program::BoundBlackBoxes,
    workspace: program::EvaluationWorkspace,
}

#[derive(Debug, Clone)]
struct CompatibilityGraph {
    nodes: Vec<Node>,
    signals: Vec<usize>,
}

impl Graph {
    fn compatibility(&self) -> &CompatibilityGraph {
        self.compatibility.get_or_init(|| {
            let (nodes, signals) = self
                .program
                .to_nodes()
                .expect("a validated witness program must expand into a valid node graph");
            CompatibilityGraph { nodes, signals }
        })
    }

    /// Returns the prepared node DAG. For fused graph files this is a semantically equivalent
    /// expansion and is not guaranteed to use the builder's original node indices.
    pub fn nodes(&self) -> &[Node] {
        &self.compatibility().nodes
    }

    /// Returns witness outputs as indices into [`Graph::nodes`].
    pub fn signals(&self) -> &[usize] {
        &self.compatibility().signals
    }

    /// Evaluates a graph using an already populated positional input buffer.
    pub fn evaluate(
        &self,
        inputs: &[U256],
        bbfs: Option<&HashMap<String, BlackBoxFunction>>,
    ) -> eyre::Result<Vec<U256>> {
        self.program.evaluate(inputs, bbfs)
    }

    /// Prepares a stateful evaluator that reuses allocations and resolves black-box callbacks once.
    pub fn evaluator(
        &self,
        bbfs: Option<&HashMap<String, BlackBoxFunction>>,
    ) -> eyre::Result<WitnessEvaluator<'_>> {
        Ok(WitnessEvaluator {
            graph: self,
            black_boxes: self.program.bind_black_boxes(bbfs)?,
            workspace: program::EvaluationWorkspace::default(),
        })
    }

    /// Returns a graph that evaluates selected DAG regions with native Rust callbacks.
    ///
    /// Node IDs in each replacement refer to this graph's [`Graph::nodes`] view. Replacements are
    /// validated as closed subgraphs: every dependency entering a region must be listed as an
    /// input, and every covered value used outside it must be listed as an output.
    pub fn customize(&self, replacements: &[custom::NativeSubgraph]) -> eyre::Result<Self> {
        self.apply_customizations(replacements, &[])
    }

    /// Starts a builder for combining native DAG replacements and dynamic runtime-function
    /// implementations in one customized graph.
    pub fn customizer(&self) -> custom::GraphCustomizer<'_> {
        custom::GraphCustomizer::new(self)
    }

    /// Names of dynamic Circom functions embedded in this graph's portable runtime IR.
    ///
    /// These are the names accepted by [`custom::RuntimeFunctionMatcher`].
    pub fn runtime_function_names(&self) -> impl ExactSizeIterator<Item = &str> {
        self.program
            .runtime_functions()
            .iter()
            .map(|function| function.name.as_str())
    }

    pub(crate) fn apply_customizations(
        &self,
        replacements: &[custom::NativeSubgraph],
        runtime_functions: &[custom::NativeRuntimeFunction],
    ) -> eyre::Result<Self> {
        if replacements.is_empty() && runtime_functions.is_empty() {
            return Ok(self.clone());
        }
        if self.program.has_customizations() {
            return Err(eyre!(
                "a customized graph cannot be customized again; register all customizations on the original graph"
            ));
        }
        let mut compatibility = self.compatibility.get().cloned();
        let program = if replacements.is_empty() {
            self.program.clone()
        } else {
            let graph = self.compatibility();
            let resolved = custom::resolve(&graph.nodes, &graph.signals, replacements)?;
            compatibility = Some(graph.clone());
            program::compile_with_native(
                &graph.nodes,
                &graph.signals,
                &[],
                self.program.runtime_functions().to_vec(),
                &resolved,
            )?
            .prepare_evaluation()?
        }
        .with_native_runtime_functions(runtime_functions.to_vec())?;
        Ok(Self {
            compatibility: compatibility.map_or_else(OnceLock::new, OnceLock::from),
            input_mapping: self.input_mapping.clone(),
            program,
        })
    }

    /// Returns the number of compact runtime instructions after graph preparation and fusion.
    #[doc(hidden)]
    pub fn runtime_instruction_count(&self) -> usize {
        self.program.instruction_count()
    }
}

impl WitnessEvaluator<'_> {
    /// Evaluates one witness, reusing buffers retained from previous calls.
    ///
    /// The returned slice is backed by this evaluator and is overwritten by its next evaluation.
    pub fn evaluate(&mut self, inputs: &[U256]) -> eyre::Result<&[U256]> {
        self.graph
            .program
            .evaluate_prepared(inputs, &self.black_boxes, &mut self.workspace)?;
        Ok(self.workspace.outputs())
    }

    pub(crate) fn evaluate_profiled(
        &mut self,
        inputs: &[U256],
        profile: &mut profile::ProfileCollector,
    ) -> eyre::Result<&[U256]> {
        self.graph.program.evaluate_prepared_profiled(
            inputs,
            &self.black_boxes,
            &mut self.workspace,
            profile,
        )?;
        Ok(self.workspace.outputs())
    }
}

#[doc(hidden)]
pub fn serialize_graph(
    nodes: Vec<Node>,
    signals: Vec<usize>,
    input_mapping: Vec<HashSignalInfo>,
) -> eyre::Result<Vec<u8>> {
    serialize_graph_with_runtime(nodes, signals, input_mapping, Vec::new())
}

#[doc(hidden)]
pub fn serialize_graph_with_runtime(
    nodes: Vec<Node>,
    signals: Vec<usize>,
    input_mapping: Vec<HashSignalInfo>,
    runtime_functions: Vec<runtime::RuntimeFunction>,
) -> eyre::Result<Vec<u8>> {
    serialize_graph_with_runtime_and_compression(
        nodes,
        signals,
        input_mapping,
        runtime_functions,
        DEFAULT_GRAPH_COMPRESSION_LEVEL,
    )
}

#[doc(hidden)]
pub fn serialize_graph_with_runtime_and_compression(
    nodes: Vec<Node>,
    signals: Vec<usize>,
    input_mapping: Vec<HashSignalInfo>,
    runtime_functions: Vec<runtime::RuntimeFunction>,
    compression_level: i32,
) -> eyre::Result<Vec<u8>> {
    validate_graph_compression_level(compression_level)?;
    // Graph generation pays for all generic fusion and scheduling once. The artifact contains the
    // exact executable layout so applications only decompress, deserialize, and validate it.
    let program = program::compile_for_serialization(&nodes, &signals, runtime_functions)?
        .prepare_evaluation()?;
    let (prepared, runtime_functions) = program.into_prepared()?;
    let postcard = postcard::to_stdvec(&(&prepared, &input_mapping, &runtime_functions))?;
    let compressed = zstd::bulk::compress(&postcard, compression_level)
        .wrap_err("failed to compress witness graph")?;
    let mut encoded = Vec::with_capacity(GRAPH_HEADER.len() + compressed.len());
    encoded.extend_from_slice(GRAPH_HEADER);
    encoded.extend_from_slice(&compressed);
    Ok(encoded)
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
    let payload = graph_bytes
        .strip_prefix(GRAPH_HEADER)
        .ok_or_else(|| eyre!("unsupported witness graph format"))?;
    let decompressed_size = zstd::zstd_safe::get_frame_content_size(payload)
        .map_err(|error| eyre!("invalid witness graph compression frame: {error:?}"))?
        .ok_or_else(|| eyre!("witness graph compression frame is missing its content size"))?;
    let decompressed_size = usize::try_from(decompressed_size)
        .map_err(|_| eyre!("witness graph is too large for this platform"))?;
    let mut decompressed = Vec::new();
    decompressed
        .try_reserve_exact(decompressed_size)
        .wrap_err("witness graph decompressed size cannot be allocated")?;
    let written = zstd::bulk::Decompressor::new()
        .wrap_err("failed to initialize witness graph decompressor")?
        .decompress_to_buffer(payload, &mut decompressed)
        .wrap_err("failed to decompress witness graph")?;
    if written != decompressed_size || decompressed.len() != decompressed_size {
        return Err(eyre!("witness graph decompressed to an unexpected size"));
    }
    let (prepared, input_mapping, runtime_functions): (
        program::PreparedProgram,
        Vec<HashSignalInfo>,
        Vec<runtime::RuntimeFunction>,
    ) = postcard::from_bytes(&decompressed).wrap_err("failed to decode prepared witness graph")?;
    let program = program::Program::from_prepared(prepared, runtime_functions)?;

    Ok(Graph {
        compatibility: OnceLock::new(),
        input_mapping,
        program,
    })
}

/// Calculates the number of needed inputs
pub fn get_inputs_size(graph: &Graph) -> usize {
    graph.program.input_count()
}

/// Allocates inputs vec with position 0 set to 1
pub fn get_inputs_buffer(size: usize) -> Vec<U256> {
    let mut inputs = vec![U256::ZERO; size];
    inputs[0] = U256::from(1);
    inputs
}

/// Calculates the position of the given signal in the inputs buffer
pub fn get_input_mapping(input_list: &[String], graph: &Graph) -> HashMap<String, usize> {
    try_get_input_mapping(input_list, graph).expect("input signal is missing from witness graph")
}

/// Fallible variant of [`get_input_mapping`] for command-line tools and untrusted input objects.
pub fn try_get_input_mapping(
    input_list: &[String],
    graph: &Graph,
) -> eyre::Result<HashMap<String, usize>> {
    let mut input_mapping = HashMap::new();
    for key in input_list {
        let h = fnv1a(key);
        let pos = graph
            .input_mapping
            .iter()
            .position(|x| x.hash == h)
            .ok_or_else(|| eyre!("input signal {key:?} is missing from witness graph"))?;
        let si = (graph.input_mapping[pos].signalid) as usize;
        input_mapping.insert(key.to_string(), si);
    }
    Ok(input_mapping)
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
    let input_names = input_list.keys().cloned().collect::<Vec<_>>();
    let input_mapping = get_input_mapping(&input_names, graph);
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
    fn fused_graph_round_trips_semantically() {
        let (nodes, signals, input_mapping) = graph_parts();
        let encoded =
            serialize_graph(nodes.clone(), signals.clone(), input_mapping.clone()).unwrap();
        assert!(encoded.starts_with(GRAPH_HEADER));

        let graph = init_graph(&encoded).unwrap();
        assert_eq!(graph.input_mapping, input_mapping);
        assert!(graph.compatibility.get().is_none());

        let mut bbfs = HashMap::<String, BlackBoxFunction>::new();
        bbfs.insert(
            "bbf_test".to_owned(),
            Arc::new(|parameters: &[Fr]| parameters.iter().copied().sum()),
        );
        let inputs = [U256::from(3_u64), U256::from(5_u64)];
        assert_eq!(
            graph::evaluate(&nodes, &inputs, &signals, Some(&bbfs)).unwrap(),
            graph.evaluate(&inputs, Some(&bbfs)).unwrap()
        );
        assert!(graph.compatibility.get().is_none());
        assert_eq!(
            graph::evaluate(graph.nodes(), &inputs, graph.signals(), Some(&bbfs)).unwrap(),
            graph.evaluate(&inputs, Some(&bbfs)).unwrap()
        );
        assert!(graph.compatibility.get().is_some());

        let expected = graph.evaluate(&inputs, Some(&bbfs)).unwrap();
        let error = graph.evaluator(None).err().unwrap();
        assert!(error
            .to_string()
            .contains("no black box functions provided"));
        let mut evaluator = graph.evaluator(Some(&bbfs)).unwrap();
        drop(bbfs);

        let first = evaluator.evaluate(&inputs).unwrap();
        assert_eq!(first, expected);
        let output_allocation = first.as_ptr();
        let second = evaluator.evaluate(&inputs).unwrap();
        assert_eq!(second, expected);
        assert_eq!(second.as_ptr(), output_allocation);
    }

    #[test]
    fn graph_compression_level_is_selected_at_serialization_time() {
        let nodes = vec![
            Node::Input(0),
            Node::Input(1),
            Node::Op(Operation::Add, 0, 1),
        ];
        let default = serialize_graph(nodes.clone(), vec![2], Vec::new()).unwrap();
        let explicit_default = serialize_graph_with_runtime_and_compression(
            nodes.clone(),
            vec![2],
            Vec::new(),
            Vec::new(),
            DEFAULT_GRAPH_COMPRESSION_LEVEL,
        )
        .unwrap();
        assert_eq!(default, explicit_default);

        let fast = serialize_graph_with_runtime_and_compression(
            nodes,
            vec![2],
            Vec::new(),
            Vec::new(),
            -5,
        )
        .unwrap();
        assert_eq!(
            init_graph(&fast)
                .unwrap()
                .evaluate(&[U256::from(2_u64), U256::from(3_u64)], None)
                .unwrap(),
            vec![U256::from(5_u64)]
        );

        let unsupported = zstd::compression_level_range()
            .end()
            .checked_add(1)
            .unwrap();
        assert!(serialize_graph_with_runtime_and_compression(
            vec![Node::Input(0)],
            vec![0],
            Vec::new(),
            Vec::new(),
            unsupported,
        )
        .is_err());
    }

    #[test]
    fn fused_graph_batches_independent_divisions() {
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
        let inputs = [U256::from(6_u64), U256::from(5_u64), U256::from(2_u64)];
        let expected = graph::evaluate(&nodes, &inputs, &outputs, None).unwrap();
        let encoded = serialize_graph(nodes, outputs, Vec::new()).unwrap();
        let graph = init_graph(&encoded).unwrap();
        assert_eq!(graph.evaluate(&inputs, None).unwrap(), expected);
        let mut evaluator = graph.evaluator(None).unwrap();
        assert_eq!(evaluator.evaluate(&inputs).unwrap(), expected);
    }

    #[test]
    fn unknown_graph_versions_are_rejected() {
        let error = init_graph(b"CWGR\x03FZ\0payload").err().unwrap();
        assert!(error
            .to_string()
            .contains("unsupported witness graph format"));
    }
}
