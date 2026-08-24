//! Process-local native replacements for witness DAG regions and dynamic Circom functions, plus
//! deterministic seed/BLAKE3 corpus recording and replay against the portable graph.

use std::{
    collections::{BTreeMap, HashSet},
    fmt,
    sync::{Arc, Mutex},
};

use ark_bn254::Fr;
use eyre::{bail, eyre, Context as _};
use ruint::aliases::U256;
use serde::{Deserialize, Serialize};

use crate::{graph::Node, BlackBoxFunction, Graph, M};

/// Native field code that replaces a subgraph.
///
/// Inputs and outputs use the order supplied to [`NativeSubgraph::new`] or
/// [`NativeSubgraph::try_new`]. The output slice is pre-sized and initialized to zero.
pub type NativeSubgraphFunction =
    Arc<dyn Fn(&[Fr], &mut [Fr]) -> eyre::Result<()> + Send + Sync + 'static>;

/// Selects runtime Circom functions by their generated name.
///
/// Circom appends numeric specialization suffixes to many function names. `NumericSuffix`
/// deliberately accepts only the exact base or `base_<digits>`, avoiding broad prefix matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeFunctionMatcher {
    Exact(String),
    NumericSuffix(String),
}

impl RuntimeFunctionMatcher {
    pub fn exact(name: impl Into<String>) -> Self {
        Self::Exact(name.into())
    }

    pub fn numeric_suffix(base: impl Into<String>) -> Self {
        Self::NumericSuffix(base.into())
    }

    pub(crate) fn matches(&self, name: &str) -> bool {
        match self {
            Self::Exact(expected) => name == expected,
            Self::NumericSuffix(base) => {
                name == base
                    || name
                        .strip_prefix(base)
                        .and_then(|suffix| suffix.strip_prefix('_'))
                        .is_some_and(|suffix| {
                            !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
                        })
            }
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        match self {
            Self::Exact(name) | Self::NumericSuffix(name) => name.is_empty(),
        }
    }

    fn default_diagnostic_name(&self) -> String {
        match self {
            Self::Exact(name) | Self::NumericSuffix(name) => name.clone(),
        }
    }
}

/// Metadata for one portable-runtime function invocation.
///
/// Arguments are flattened exactly as Circom passes them. [`RuntimeCallInfo::argument`] restores
/// their original top-level boundaries, which is essential for bigint kernels whose arrays have
/// specialized lengths at each call site.
#[derive(Debug, Clone, Copy)]
pub struct RuntimeCallInfo<'a> {
    function_id: usize,
    function_name: &'a str,
    arguments: &'a [Fr],
    argument_sizes: &'a [usize],
    arena_size: usize,
    result_count: usize,
}

impl<'a> RuntimeCallInfo<'a> {
    pub(crate) fn new(
        function_id: usize,
        function_name: &'a str,
        arguments: &'a [Fr],
        argument_sizes: &'a [usize],
        arena_size: usize,
        result_count: usize,
    ) -> Self {
        Self {
            function_id,
            function_name,
            arguments,
            argument_sizes,
            arena_size,
            result_count,
        }
    }

    pub fn function_id(self) -> usize {
        self.function_id
    }

    pub fn function_name(self) -> &'a str {
        self.function_name
    }

    pub fn arguments(self) -> &'a [Fr] {
        self.arguments
    }

    pub fn argument_sizes(self) -> &'a [usize] {
        self.argument_sizes
    }

    pub fn argument(self, index: usize) -> Option<&'a [Fr]> {
        let start = self
            .argument_sizes
            .get(..index)?
            .iter()
            .try_fold(0_usize, |total, size| total.checked_add(*size))?;
        let end = start.checked_add(*self.argument_sizes.get(index)?)?;
        self.arguments.get(start..end)
    }

    pub fn arena_size(self) -> usize {
        self.arena_size
    }

    pub fn result_count(self) -> usize {
        self.result_count
    }
}

/// Result of trying a native runtime-function implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeRuntimeOutcome {
    /// The callback populated the complete output slice.
    Handled,
    /// This call shape is unsupported; try another handler or the portable interpreter.
    Fallback,
}

/// One runtime call shape observed by an optionally tracked native handler.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct NativeRuntimeCallShape {
    pub function_id: usize,
    pub function_name: String,
    pub argument_sizes: Vec<usize>,
    pub arena_size: usize,
    pub result_count: usize,
}

impl NativeRuntimeCallShape {
    fn from_call(call: RuntimeCallInfo<'_>) -> Self {
        Self {
            function_id: call.function_id(),
            function_name: call.function_name().to_owned(),
            argument_sizes: call.argument_sizes().to_vec(),
            arena_size: call.arena_size(),
            result_count: call.result_count(),
        }
    }
}

/// Counts for one call shape in a [`NativeRuntimeCoverageSnapshot`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NativeRuntimeShapeCoverage {
    pub shape: NativeRuntimeCallShape,
    pub attempts: u64,
    pub handled: u64,
    pub fallbacks: u64,
    pub errors: u64,
}

/// Point-in-time coverage for one named native runtime handler.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NativeRuntimeCoverageSnapshot {
    pub handler_name: String,
    pub attempts: u64,
    pub handled: u64,
    pub fallbacks: u64,
    pub errors: u64,
    pub shapes: Vec<NativeRuntimeShapeCoverage>,
}

#[derive(Debug, Default, Clone, Copy)]
struct CoverageCounts {
    attempts: u64,
    handled: u64,
    fallbacks: u64,
    errors: u64,
}

#[derive(Debug, Default)]
struct CoverageState {
    total: CoverageCounts,
    shapes: BTreeMap<NativeRuntimeCallShape, CoverageCounts>,
}

/// Shared handle for inspecting an opt-in native runtime handler's coverage.
#[derive(Debug, Clone)]
pub struct NativeRuntimeCoverage {
    handler_name: String,
    state: Arc<Mutex<CoverageState>>,
}

impl NativeRuntimeCoverage {
    fn new(handler_name: String) -> Self {
        Self {
            handler_name,
            state: Arc::new(Mutex::new(CoverageState::default())),
        }
    }

    fn begin(&self, call: RuntimeCallInfo<'_>) -> NativeRuntimeCallShape {
        let shape = NativeRuntimeCallShape::from_call(call);
        let mut state = self
            .state
            .lock()
            .expect("native coverage lock was poisoned");
        state.total.attempts += 1;
        state.shapes.entry(shape.clone()).or_default().attempts += 1;
        shape
    }

    fn finish(&self, shape: &NativeRuntimeCallShape, result: &eyre::Result<NativeRuntimeOutcome>) {
        let mut state = self
            .state
            .lock()
            .expect("native coverage lock was poisoned");
        match result {
            Ok(NativeRuntimeOutcome::Handled) => {
                state.total.handled += 1;
                state
                    .shapes
                    .get_mut(shape)
                    .expect("a completed native call must have a coverage entry")
                    .handled += 1;
            }
            Ok(NativeRuntimeOutcome::Fallback) => {
                state.total.fallbacks += 1;
                state
                    .shapes
                    .get_mut(shape)
                    .expect("a completed native call must have a coverage entry")
                    .fallbacks += 1;
            }
            Err(_) => {
                state.total.errors += 1;
                state
                    .shapes
                    .get_mut(shape)
                    .expect("a completed native call must have a coverage entry")
                    .errors += 1;
            }
        }
    }

    /// Returns accumulated counts without resetting them.
    pub fn snapshot(&self) -> NativeRuntimeCoverageSnapshot {
        let state = self
            .state
            .lock()
            .expect("native coverage lock was poisoned");
        NativeRuntimeCoverageSnapshot {
            handler_name: self.handler_name.clone(),
            attempts: state.total.attempts,
            handled: state.total.handled,
            fallbacks: state.total.fallbacks,
            errors: state.total.errors,
            shapes: state
                .shapes
                .iter()
                .map(|(shape, counts)| NativeRuntimeShapeCoverage {
                    shape: shape.clone(),
                    attempts: counts.attempts,
                    handled: counts.handled,
                    fallbacks: counts.fallbacks,
                    errors: counts.errors,
                })
                .collect(),
        }
    }
}

pub type NativeRuntimeFunctionCallback = Arc<
    dyn for<'a> Fn(RuntimeCallInfo<'a>, &mut [Fr]) -> eyre::Result<NativeRuntimeOutcome>
        + Send
        + Sync
        + 'static,
>;

/// Optional native implementation of a dynamic Circom function.
///
/// Every invocation, including calls nested inside portable runtime IR, passes through matching
/// handlers. A handler may decline a call shape with [`NativeRuntimeOutcome::Fallback`].
#[derive(Clone)]
pub struct NativeRuntimeFunction {
    name: String,
    matcher: RuntimeFunctionMatcher,
    function: NativeRuntimeFunctionCallback,
    coverage: Option<NativeRuntimeCoverage>,
}

impl fmt::Debug for NativeRuntimeFunction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeRuntimeFunction")
            .field("name", &self.name)
            .field("matcher", &self.matcher)
            .finish_non_exhaustive()
    }
}

impl NativeRuntimeFunction {
    pub fn new(
        matcher: RuntimeFunctionMatcher,
        function: impl for<'a> Fn(RuntimeCallInfo<'a>, &mut [Fr]) -> NativeRuntimeOutcome
            + Send
            + Sync
            + 'static,
    ) -> Self {
        let name = matcher.default_diagnostic_name();
        Self::named(name, matcher, function)
    }

    /// Creates an infallible handler with a stable diagnostic name.
    pub fn named(
        name: impl Into<String>,
        matcher: RuntimeFunctionMatcher,
        function: impl for<'a> Fn(RuntimeCallInfo<'a>, &mut [Fr]) -> NativeRuntimeOutcome
            + Send
            + Sync
            + 'static,
    ) -> Self {
        Self::try_named(name, matcher, move |call, outputs| {
            Ok(function(call, outputs))
        })
    }

    pub fn try_new(
        matcher: RuntimeFunctionMatcher,
        function: impl for<'a> Fn(RuntimeCallInfo<'a>, &mut [Fr]) -> eyre::Result<NativeRuntimeOutcome>
            + Send
            + Sync
            + 'static,
    ) -> Self {
        let name = matcher.default_diagnostic_name();
        Self::try_named(name, matcher, function)
    }

    /// Creates a fallible handler with a stable diagnostic name.
    pub fn try_named(
        name: impl Into<String>,
        matcher: RuntimeFunctionMatcher,
        function: impl for<'a> Fn(RuntimeCallInfo<'a>, &mut [Fr]) -> eyre::Result<NativeRuntimeOutcome>
            + Send
            + Sync
            + 'static,
    ) -> Self {
        Self {
            name: name.into(),
            matcher,
            function: Arc::new(function),
            coverage: None,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn matcher(&self) -> &RuntimeFunctionMatcher {
        &self.matcher
    }

    /// Enables call-shape coverage for this handler and returns the shared inspection handle.
    ///
    /// Tracking is opt-in because it adds synchronization to each attempted call. Keep it disabled
    /// for final performance measurements.
    pub fn tracked(mut self) -> (Self, NativeRuntimeCoverage) {
        let coverage = NativeRuntimeCoverage::new(self.name.clone());
        self.coverage = Some(coverage.clone());
        (self, coverage)
    }

    pub(crate) fn evaluate(
        &self,
        call: RuntimeCallInfo<'_>,
        outputs: &mut [Fr],
    ) -> eyre::Result<NativeRuntimeOutcome> {
        let shape = self.coverage.as_ref().map(|coverage| coverage.begin(call));
        let result = (self.function)(call, outputs);
        if let (Some(coverage), Some(shape)) = (&self.coverage, shape) {
            coverage.finish(&shape, &result);
        }
        result
    }
}

/// Collects all process-local optimizations before building a customized graph.
pub struct GraphCustomizer<'graph> {
    pub(crate) graph: &'graph Graph,
    pub(crate) subgraphs: Vec<NativeSubgraph>,
    pub(crate) runtime_functions: Vec<NativeRuntimeFunction>,
}

impl<'graph> GraphCustomizer<'graph> {
    pub(crate) fn new(graph: &'graph Graph) -> Self {
        Self {
            graph,
            subgraphs: Vec::new(),
            runtime_functions: Vec::new(),
        }
    }

    pub fn native_subgraph(mut self, replacement: NativeSubgraph) -> Self {
        self.subgraphs.push(replacement);
        self
    }

    pub fn native_subgraphs(
        mut self,
        replacements: impl IntoIterator<Item = NativeSubgraph>,
    ) -> Self {
        self.subgraphs.extend(replacements);
        self
    }

    pub fn runtime_function(mut self, function: NativeRuntimeFunction) -> Self {
        self.runtime_functions.push(function);
        self
    }

    pub fn runtime_functions(
        mut self,
        functions: impl IntoIterator<Item = NativeRuntimeFunction>,
    ) -> Self {
        self.runtime_functions.extend(functions);
        self
    }

    pub fn build(self) -> eyre::Result<Graph> {
        self.graph
            .apply_customizations(&self.subgraphs, &self.runtime_functions)
    }
}

/// Describes one graph region that should be evaluated by native Rust code.
///
/// `inputs` and `outputs` are node IDs in [`Graph::nodes`]. All dependencies between the outputs
/// and the input boundary are replaced. Constants inside the region are deliberately not passed to
/// the callback: optimized code is expected to bake them in.
#[derive(Clone)]
pub struct NativeSubgraph {
    name: String,
    inputs: Vec<usize>,
    outputs: Vec<usize>,
    function: NativeSubgraphFunction,
}

impl fmt::Debug for NativeSubgraph {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeSubgraph")
            .field("name", &self.name)
            .field("inputs", &self.inputs)
            .field("outputs", &self.outputs)
            .finish_non_exhaustive()
    }
}

impl NativeSubgraph {
    /// Creates an infallible native replacement.
    pub fn new(
        name: impl Into<String>,
        inputs: Vec<usize>,
        outputs: Vec<usize>,
        function: impl Fn(&[Fr], &mut [Fr]) + Send + Sync + 'static,
    ) -> Self {
        Self::try_new(name, inputs, outputs, move |inputs, outputs| {
            function(inputs, outputs);
            Ok(())
        })
    }

    /// Creates a native replacement that may report an evaluation error.
    pub fn try_new(
        name: impl Into<String>,
        inputs: Vec<usize>,
        outputs: Vec<usize>,
        function: impl Fn(&[Fr], &mut [Fr]) -> eyre::Result<()> + Send + Sync + 'static,
    ) -> Self {
        Self {
            name: name.into(),
            inputs,
            outputs,
            function: Arc::new(function),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn inputs(&self) -> &[usize] {
        &self.inputs
    }

    pub fn outputs(&self) -> &[usize] {
        &self.outputs
    }
}

#[derive(Clone)]
pub(crate) struct ResolvedNativeSubgraph {
    pub(crate) name: String,
    pub(crate) inputs: Vec<usize>,
    pub(crate) outputs: Vec<usize>,
    pub(crate) covered: Vec<usize>,
    pub(crate) function: NativeSubgraphFunction,
}

fn visit_dependencies(node: &Node, mut visit: impl FnMut(usize)) {
    match node {
        Node::Op(_, left, right) => {
            visit(*left);
            visit(*right);
        }
        Node::BBF(_, parameters) | Node::RuntimeCall { parameters, .. } => {
            parameters.iter().copied().for_each(visit)
        }
        Node::Input(_) | Node::Constant(_) | Node::MontConstant(_) => {}
    }
}

pub(crate) fn resolve(
    nodes: &[Node],
    graph_outputs: &[usize],
    replacements: &[NativeSubgraph],
) -> eyre::Result<Vec<ResolvedNativeSubgraph>> {
    let mut resolved = Vec::with_capacity(replacements.len());
    let mut owners = vec![None::<usize>; nodes.len()];

    for (replacement_index, replacement) in replacements.iter().enumerate() {
        if replacement.name.is_empty() {
            bail!("native subgraph names must not be empty");
        }
        if replacement.outputs.is_empty() {
            bail!("native subgraph {:?} has no outputs", replacement.name);
        }

        let inputs = replacement.inputs.iter().copied().collect::<HashSet<_>>();
        let outputs = replacement.outputs.iter().copied().collect::<HashSet<_>>();
        if inputs.len() != replacement.inputs.len() {
            bail!(
                "native subgraph {:?} has duplicate inputs",
                replacement.name
            );
        }
        if outputs.len() != replacement.outputs.len() {
            bail!(
                "native subgraph {:?} has duplicate outputs",
                replacement.name
            );
        }
        if let Some(node) = inputs.intersection(&outputs).next() {
            bail!(
                "native subgraph {:?} uses node {node} as both input and output",
                replacement.name
            );
        }
        for &node in inputs.union(&outputs) {
            if node >= nodes.len() {
                bail!(
                    "native subgraph {:?} references out-of-bounds node {node}",
                    replacement.name
                );
            }
        }

        let activation = *replacement.outputs.iter().min().unwrap();
        if let Some(&input) = replacement
            .inputs
            .iter()
            .find(|&&input| input >= activation)
        {
            bail!(
                "native subgraph {:?} input node {input} is not earlier than its first output node {activation}",
                replacement.name
            );
        }

        let mut covered = HashSet::new();
        let mut reached_inputs = HashSet::new();
        let mut pending = replacement.outputs.clone();
        while let Some(node) = pending.pop() {
            if inputs.contains(&node) {
                reached_inputs.insert(node);
                continue;
            }
            // Constants are implicit leaves of a native region. They are deliberately not owned
            // by the replacement: the callback bakes their values into native code, while the
            // same pooled constant node remains available to other replacements and portable
            // graph instructions.
            if matches!(nodes[node], Node::Constant(_) | Node::MontConstant(_)) {
                continue;
            }
            if !covered.insert(node) {
                continue;
            }
            match &nodes[node] {
                Node::Input(input) => bail!(
                    "native subgraph {:?} reaches graph input {input} at node {node}; add that node to its input boundary",
                    replacement.name
                ),
                node => visit_dependencies(node, |dependency| pending.push(dependency)),
            }
        }
        if reached_inputs.len() != inputs.len() {
            let unused = replacement
                .inputs
                .iter()
                .find(|node| !reached_inputs.contains(node))
                .unwrap();
            bail!(
                "native subgraph {:?} input node {unused} is not a dependency of its outputs",
                replacement.name
            );
        }

        let mut covered = covered.into_iter().collect::<Vec<_>>();
        covered.sort_unstable();
        for &node in &covered {
            if let Some(owner) = owners[node] {
                bail!(
                    "native subgraphs {:?} and {:?} overlap at node {node}",
                    replacements[owner].name,
                    replacement.name
                );
            }
            owners[node] = Some(replacement_index);
        }

        resolved.push(ResolvedNativeSubgraph {
            name: replacement.name.clone(),
            inputs: replacement.inputs.clone(),
            outputs: replacement.outputs.clone(),
            covered,
            function: replacement.function.clone(),
        });
    }

    let output_sets = resolved
        .iter()
        .map(|replacement| replacement.outputs.iter().copied().collect::<HashSet<_>>())
        .collect::<Vec<_>>();
    for (user, node) in nodes.iter().enumerate() {
        let mut error = None;
        visit_dependencies(node, |dependency| {
            if let Some(owner) = owners[dependency] {
                if owners[user] != Some(owner) && !output_sets[owner].contains(&dependency) {
                    error = Some(eyre!(
                        "native subgraph {:?} hides node {dependency}, but graph node {user} uses it; add node {dependency} to the output boundary",
                        resolved[owner].name
                    ));
                }
            }
        });
        if let Some(error) = error {
            return Err(error);
        }
    }
    for &output in graph_outputs {
        if let Some(owner) = owners[output] {
            if !output_sets[owner].contains(&output) {
                bail!(
                    "native subgraph {:?} hides witness output node {output}; add it to the output boundary",
                    resolved[owner].name
                );
            }
        }
    }
    for (replacement_index, replacement) in resolved.iter().enumerate() {
        debug_assert!(replacement
            .covered
            .iter()
            .all(|&node| owners[node] == Some(replacement_index)));
    }

    Ok(resolved)
}

/// Configuration for deterministic random witness generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FuzzConfig {
    /// Number of random witnesses to generate.
    pub cases: usize,
    /// Reproducible random seed.
    pub seed: u64,
}

impl Default for FuzzConfig {
    fn default() -> Self {
        Self {
            cases: 16,
            seed: 0x6377_7273_5f66_757a,
        }
    }
}

/// One pregenerated random input and the BLAKE3 hash of its canonical witness.
///
/// Inputs are regenerated from `seed`; the potentially very large witness is intentionally not
/// stored. Circuit-specific constraint hooks must therefore be deterministic for a given seed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FuzzCorpusCase {
    pub seed: u64,
    pub witness_blake3: String,
}

/// Replayable fuzz corpus serialized as an array containing only seed/hash pairs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FuzzCorpus {
    cases: Vec<FuzzCorpusCase>,
}

impl FuzzCorpus {
    pub fn cases(&self) -> &[FuzzCorpusCase] {
        &self.cases
    }

    pub fn len(&self) -> usize {
        self.cases.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cases.is_empty()
    }
}

/// Successful replay of a pregenerated fuzz corpus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FuzzCorpusReport {
    pub cases: usize,
}

fn fuzz_inputs(input_count: usize, seed: u64) -> Vec<U256> {
    let mut inputs = vec![U256::ZERO; input_count];
    for (index, input) in inputs.iter_mut().enumerate() {
        let mut attempt = 0_u64;
        loop {
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"circom-witness-rs/fuzz-input/v1\0");
            hasher.update(&seed.to_le_bytes());
            hasher.update(&(index as u64).to_le_bytes());
            hasher.update(&attempt.to_le_bytes());
            let candidate = U256::from_le_bytes::<32>(*hasher.finalize().as_bytes());
            if candidate < M {
                *input = candidate;
                break;
            }
            attempt = attempt.wrapping_add(1);
        }
    }
    inputs
}

fn finish_fuzz_inputs(
    mut inputs: Vec<U256>,
    seed: u64,
    constrain: &mut impl FnMut(u64, &mut [U256]),
) -> Vec<U256> {
    constrain(seed, &mut inputs);
    if let Some(constant_one) = inputs.first_mut() {
        *constant_one = U256::ONE;
    }
    inputs
}

fn witness_blake3(witness: &[U256]) -> blake3::Hash {
    const FIELDS_PER_CHUNK: usize = 1_024;

    let mut hasher = blake3::Hasher::new();
    hasher.update(b"circom-witness-rs/fuzz-witness/v1\0");
    hasher.update(&(witness.len() as u64).to_le_bytes());
    let mut bytes = vec![0_u8; FIELDS_PER_CHUNK * 32];
    for fields in witness.chunks(FIELDS_PER_CHUNK) {
        for (value, encoded) in fields.iter().zip(bytes.as_chunks_mut::<32>().0) {
            encoded.copy_from_slice(&value.to_le_bytes::<32>());
        }
        hasher.update(&bytes[..fields.len() * 32]);
    }
    hasher.finalize()
}

/// Pregenerates deterministic random inputs with the original graph and records only seed/hash
/// pairs. Run this slow oracle phase once, outside the autoresearch optimization loop.
pub fn record_fuzz_corpus(
    original: &Graph,
    config: FuzzConfig,
    bbfs: Option<&std::collections::HashMap<String, BlackBoxFunction>>,
) -> eyre::Result<FuzzCorpus> {
    record_fuzz_corpus_with(original, config, bbfs, |_, _| {})
}

/// [`record_fuzz_corpus`] with deterministic circuit-specific input constraints.
///
/// The hook receives the stored seed, rather than its position in the corpus, so each case remains
/// independently reproducible if the corpus is reordered or reduced.
pub fn record_fuzz_corpus_with(
    original: &Graph,
    config: FuzzConfig,
    bbfs: Option<&std::collections::HashMap<String, BlackBoxFunction>>,
    mut constrain: impl FnMut(u64, &mut [U256]),
) -> eyre::Result<FuzzCorpus> {
    if config.cases == 0 {
        bail!("a fuzz corpus must contain at least one case");
    }
    let input_count = original.program.input_count();
    let mut evaluator = original
        .evaluator(bbfs)
        .wrap_err("failed to prepare original graph")?;
    let mut cases = Vec::with_capacity(config.cases);
    for case in 0..config.cases {
        let seed = config.seed.wrapping_add(case as u64);
        let inputs = finish_fuzz_inputs(fuzz_inputs(input_count, seed), seed, &mut constrain);
        let witness = evaluator.evaluate(&inputs).wrap_err_with(|| {
            format!("original graph failed while recording fuzz case {case}, seed {seed}")
        })?;
        cases.push(FuzzCorpusCase {
            seed,
            witness_blake3: witness_blake3(witness).to_hex().to_string(),
        });
    }
    Ok(FuzzCorpus { cases })
}

/// Replays pregenerated seeds against an optimized graph and compares BLAKE3 witness hashes.
/// The original graph is not evaluated, making this suitable for the autoresearch inner loop.
pub fn verify_fuzz_corpus(
    optimized: &Graph,
    corpus: &FuzzCorpus,
    bbfs: Option<&std::collections::HashMap<String, BlackBoxFunction>>,
) -> eyre::Result<FuzzCorpusReport> {
    verify_fuzz_corpus_with(optimized, corpus, bbfs, |_, _| {})
}

/// [`verify_fuzz_corpus`] with the same deterministic seed-based constraint hook used while
/// recording.
pub fn verify_fuzz_corpus_with(
    optimized: &Graph,
    corpus: &FuzzCorpus,
    bbfs: Option<&std::collections::HashMap<String, BlackBoxFunction>>,
    mut constrain: impl FnMut(u64, &mut [U256]),
) -> eyre::Result<FuzzCorpusReport> {
    if corpus.is_empty() {
        bail!("a fuzz corpus must contain at least one case");
    }
    let input_count = optimized.program.input_count();
    let mut evaluator = optimized
        .evaluator(bbfs)
        .wrap_err("failed to prepare optimized graph")?;
    for (case, expected) in corpus.cases.iter().enumerate() {
        let expected_hash = blake3::Hash::from_hex(&expected.witness_blake3)
            .wrap_err_with(|| format!("invalid BLAKE3 hash in fuzz case {case}"))?;
        let inputs = finish_fuzz_inputs(
            fuzz_inputs(input_count, expected.seed),
            expected.seed,
            &mut constrain,
        );
        let witness = evaluator.evaluate(&inputs).wrap_err_with(|| {
            format!(
                "optimized graph failed while replaying fuzz case {case}, seed {}",
                expected.seed
            )
        })?;
        let actual_hash = witness_blake3(witness);
        if actual_hash != expected_hash {
            bail!(
                "witness hash mismatch in fuzz case {case}, seed {} (expected {}, got {})",
                expected.seed,
                expected_hash.to_hex(),
                actual_hash.to_hex()
            );
        }
    }
    Ok(FuzzCorpusReport {
        cases: corpus.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        graph::Operation,
        init_graph,
        runtime::{RuntimeExpression, RuntimeFunction, RuntimeOperation, RuntimeStatement},
        serialize_graph, serialize_graph_with_runtime,
    };
    use ark_ff::Field as _;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn arithmetic_graph() -> Graph {
        let nodes = vec![
            Node::Input(0),
            Node::Input(1),
            Node::Op(Operation::Add, 0, 1),
            Node::Op(Operation::Mul, 2, 2),
            Node::Op(Operation::Div, 3, 1),
        ];
        init_graph(&serialize_graph(nodes, vec![2, 3, 4], Vec::new()).unwrap()).unwrap()
    }

    #[test]
    fn numeric_suffix_matcher_does_not_match_unrelated_prefixes() {
        let matcher = RuntimeFunctionMatcher::numeric_suffix("long_div2");
        assert!(matcher.matches("long_div2"));
        assert!(matcher.matches("long_div2_17"));
        assert!(!matcher.matches("long_div20"));
        assert!(!matcher.matches("long_div2_custom"));
    }

    fn load(offset: usize, size: usize) -> RuntimeExpression {
        RuntimeExpression::Load {
            offset: Box::new(RuntimeExpression::Address(offset)),
            size,
        }
    }

    fn runtime_graph() -> Graph {
        let inner = RuntimeFunction {
            name: "bigint_kernel_7".to_owned(),
            variable_count: 3,
            body: vec![
                RuntimeStatement::Store {
                    offset: RuntimeExpression::Address(0),
                    size: 1,
                    value: RuntimeExpression::Compute {
                        operation: RuntimeOperation::Field(Operation::Add),
                        operands: vec![load(0, 1), load(2, 1)],
                    },
                },
                RuntimeStatement::Store {
                    offset: RuntimeExpression::Address(1),
                    size: 1,
                    value: RuntimeExpression::Compute {
                        operation: RuntimeOperation::Field(Operation::Mul),
                        operands: vec![load(1, 1), load(2, 1)],
                    },
                },
                RuntimeStatement::Return {
                    value: load(0, 2),
                    size: 2,
                },
            ],
        };
        let outer = RuntimeFunction {
            name: "outer".to_owned(),
            variable_count: 3,
            body: vec![RuntimeStatement::Return {
                value: RuntimeExpression::Call {
                    function: 0,
                    arena_size: 3,
                    result_size: 2,
                    arguments: vec![(load(0, 2), 2), (load(2, 1), 1)],
                },
                size: 2,
            }],
        };
        let nodes = vec![
            Node::Input(0),
            Node::Input(1),
            Node::Input(2),
            Node::RuntimeCall {
                function: 1,
                call: 0,
                output: 0,
                output_count: 2,
                arena_size: 3,
                argument_sizes: vec![2, 1],
                parameters: vec![0, 1, 2],
            },
            Node::RuntimeCall {
                function: 1,
                call: 0,
                output: 1,
                output_count: 2,
                arena_size: 3,
                argument_sizes: vec![2, 1],
                parameters: vec![0, 1, 2],
            },
        ];
        init_graph(
            &serialize_graph_with_runtime(nodes, vec![3, 4], Vec::new(), vec![inner, outer])
                .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn multi_output_native_subgraph_replaces_a_closed_region() {
        let original = arithmetic_graph();
        let replacement = NativeSubgraph::new(
            "sum-and-square",
            vec![0, 1],
            vec![2, 3],
            |inputs, outputs| {
                outputs[0] = inputs[0] + inputs[1];
                outputs[1] = outputs[0].square();
            },
        );
        let optimized = original.customize(&[replacement]).unwrap();

        assert!(optimized.runtime_instruction_count() < original.runtime_instruction_count());
        let corpus =
            record_fuzz_corpus(&original, FuzzConfig { cases: 32, seed: 7 }, None).unwrap();
        assert_eq!(
            verify_fuzz_corpus(&optimized, &corpus, None).unwrap().cases,
            32
        );
    }

    #[test]
    fn fuzz_seed_mapping_has_a_stable_golden_vector() {
        let inputs = finish_fuzz_inputs(fuzz_inputs(4, 41), 41_u64, &mut |_, _| {});
        let expected = [
            "1",
            "12582430194538003854020091743819204928138720569990892351889268536201142994086",
            "1131272633747086338100786788918863750075083162243258060160111143945156737083",
            "10044629985142331560893454010639311256461967596594112127128116628680634758565",
        ]
        .map(|value| value.parse::<U256>().unwrap());
        assert_eq!(inputs, expected);
    }

    #[test]
    fn pregenerated_fuzz_corpus_stores_and_replays_only_seed_hash_pairs() {
        let original = arithmetic_graph();
        let replacement = NativeSubgraph::new(
            "sum-and-square",
            vec![0, 1],
            vec![2, 3],
            |inputs, outputs| {
                outputs[0] = inputs[0] + inputs[1];
                outputs[1] = outputs[0].square();
            },
        );
        let optimized = original.customize(&[replacement]).unwrap();
        let corpus =
            record_fuzz_corpus(&original, FuzzConfig { cases: 3, seed: 41 }, None).unwrap();

        assert_eq!(
            corpus
                .cases()
                .iter()
                .map(|case| case.seed)
                .collect::<Vec<_>>(),
            vec![41, 42, 43]
        );
        let serialized = serde_json::to_value(&corpus).unwrap();
        let cases = serialized.as_array().unwrap();
        assert_eq!(cases.len(), 3);
        assert!(cases.iter().all(|case| {
            let case = case.as_object().unwrap();
            case.len() == 2 && case.contains_key("seed") && case.contains_key("witness_blake3")
        }));
        assert!(corpus
            .cases()
            .iter()
            .all(|case| case.witness_blake3.len() == 64));

        let decoded: FuzzCorpus = serde_json::from_value(serialized).unwrap();
        assert_eq!(decoded, corpus);
        assert_eq!(
            verify_fuzz_corpus(&optimized, &decoded, None)
                .unwrap()
                .cases,
            3
        );

        let mut corrupt = decoded;
        corrupt.cases[1].witness_blake3 = "00".repeat(32);
        let error = verify_fuzz_corpus(&optimized, &corrupt, None).unwrap_err();
        assert!(error.to_string().contains("seed 42"));
    }

    #[test]
    fn constrained_corpus_cases_remain_reproducible_when_reordered() {
        let graph = arithmetic_graph();
        let config = FuzzConfig { cases: 3, seed: 51 };
        let mut corpus = record_fuzz_corpus_with(&graph, config, None, |seed, inputs| {
            inputs[1] = U256::from(seed);
        })
        .unwrap();
        corpus.cases.reverse();

        assert_eq!(
            verify_fuzz_corpus_with(&graph, &corpus, None, |seed, inputs| {
                inputs[1] = U256::from(seed);
            })
            .unwrap()
            .cases,
            3
        );
    }

    #[test]
    fn native_subgraphs_may_share_implicit_constants() {
        let nodes = vec![
            Node::Input(0),
            Node::Constant(U256::ONE),
            Node::Op(Operation::Shr, 0, 1),
            Node::Op(Operation::Band, 2, 1),
            Node::Op(Operation::Shr, 0, 1),
            Node::Op(Operation::Band, 4, 1),
        ];
        let replacements = [3_usize, 5].map(|output| {
            NativeSubgraph::new(
                format!("shared-constant-{output}"),
                vec![0],
                vec![output],
                |inputs, outputs| {
                    let value: U256 = inputs[0].into();
                    outputs[0] = Fr::from(value.bit(1));
                },
            )
        });
        let resolved = resolve(&nodes, &[3, 5], &replacements).unwrap();
        assert_eq!(resolved.len(), 2);
        assert!(resolved
            .iter()
            .all(|replacement| !replacement.covered.contains(&1)));
    }

    #[test]
    fn customization_rejects_a_covered_value_that_escapes() {
        let nodes = vec![
            Node::Input(0),
            Node::Input(1),
            Node::Op(Operation::Add, 0, 1),
            Node::Op(Operation::Mul, 2, 2),
            Node::Op(Operation::Add, 2, 1),
        ];
        let graph = init_graph(&serialize_graph(nodes, vec![3, 4], Vec::new()).unwrap()).unwrap();
        let replacement =
            NativeSubgraph::new("incomplete", vec![0, 1], vec![3], |inputs, outputs| {
                outputs[0] = (inputs[0] + inputs[1]).square()
            });
        let error = graph.customize(&[replacement]).err().unwrap();
        assert!(error
            .to_string()
            .contains("add node 2 to the output boundary"));
    }

    #[test]
    fn corpus_replay_reports_reproducible_mismatches() {
        let original = arithmetic_graph();
        let replacement = NativeSubgraph::new(
            "wrong-on-purpose",
            vec![0, 1],
            vec![2, 3],
            |inputs, outputs| {
                outputs[0] = inputs[0] + inputs[1];
                outputs[1] = outputs[0];
            },
        );
        let optimized = original.customize(&[replacement]).unwrap();
        let corpus = record_fuzz_corpus(&original, FuzzConfig { cases: 1, seed: 9 }, None).unwrap();
        let error = verify_fuzz_corpus(&optimized, &corpus, None).unwrap_err();
        let error = error.to_string();
        assert!(error.contains("fuzz case 0"));
        assert!(error.contains("seed 9"));
    }

    #[test]
    fn runtime_handlers_receive_nested_calls_boundaries_and_multiple_outputs() {
        let original = runtime_graph();
        assert_eq!(
            original.runtime_function_names().collect::<Vec<_>>(),
            vec!["bigint_kernel_7", "outer"]
        );
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_handler = calls.clone();
        let fallback = NativeRuntimeFunction::new(
            RuntimeFunctionMatcher::numeric_suffix("bigint_kernel"),
            |_call, outputs| {
                outputs.fill(Fr::from(99_u64));
                NativeRuntimeOutcome::Fallback
            },
        );
        let handler = NativeRuntimeFunction::named(
            "test-bigint-kernel",
            RuntimeFunctionMatcher::numeric_suffix("bigint_kernel"),
            move |call, outputs| {
                assert_eq!(call.function_name(), "bigint_kernel_7");
                assert_eq!(call.argument_sizes(), &[2, 1]);
                assert_eq!(call.argument(0).unwrap().len(), 2);
                assert_eq!(call.argument(1).unwrap().len(), 1);
                assert_eq!(call.result_count(), 2);
                assert_eq!(outputs, &[Fr::from(0_u64), Fr::from(0_u64)]);
                let pair = call.argument(0).unwrap();
                let scalar = call.argument(1).unwrap()[0];
                outputs[0] = pair[0] + scalar;
                outputs[1] = pair[1] * scalar;
                calls_for_handler.fetch_add(1, Ordering::Relaxed);
                NativeRuntimeOutcome::Handled
            },
        );
        let (handler, coverage) = handler.tracked();
        let optimized = original
            .customizer()
            .runtime_function(fallback)
            .runtime_function(handler)
            .build()
            .unwrap();

        let corpus =
            record_fuzz_corpus(&original, FuzzConfig { cases: 8, seed: 11 }, None).unwrap();
        verify_fuzz_corpus(&optimized, &corpus, None).unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 8);
        let coverage = coverage.snapshot();
        assert_eq!(coverage.handler_name, "test-bigint-kernel");
        assert_eq!(coverage.attempts, 8);
        assert_eq!(coverage.handled, 8);
        assert_eq!(coverage.fallbacks, 0);
        assert_eq!(coverage.errors, 0);
        assert_eq!(coverage.shapes.len(), 1);
        assert_eq!(coverage.shapes[0].shape.function_name, "bigint_kernel_7");
        assert_eq!(coverage.shapes[0].shape.argument_sizes, [2, 1]);
        assert_eq!(coverage.shapes[0].shape.result_count, 2);
    }

    #[test]
    fn declined_runtime_handler_uses_the_portable_interpreter() {
        let original = runtime_graph();
        let optimized = original
            .customizer()
            .runtime_function(NativeRuntimeFunction::new(
                RuntimeFunctionMatcher::exact("bigint_kernel_7"),
                |_call, outputs| {
                    outputs.fill(Fr::from(99_u64));
                    NativeRuntimeOutcome::Fallback
                },
            ))
            .build()
            .unwrap();

        let corpus =
            record_fuzz_corpus(&original, FuzzConfig { cases: 8, seed: 12 }, None).unwrap();
        verify_fuzz_corpus(&optimized, &corpus, None).unwrap();
    }
}
