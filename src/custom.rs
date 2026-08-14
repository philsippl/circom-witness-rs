//! Process-local native replacements for witness DAG regions and dynamic Circom functions, plus
//! deterministic differential testing against the portable graph.

use std::{collections::HashSet, fmt, sync::Arc};

use ark_bn254::Fr;
use eyre::{bail, eyre, Context as _};
use rand::{rngs::StdRng, Rng as _, SeedableRng as _};
use ruint::aliases::U256;

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
    matcher: RuntimeFunctionMatcher,
    function: NativeRuntimeFunctionCallback,
}

impl fmt::Debug for NativeRuntimeFunction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeRuntimeFunction")
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
        Self::try_new(matcher, move |call, outputs| Ok(function(call, outputs)))
    }

    pub fn try_new(
        matcher: RuntimeFunctionMatcher,
        function: impl for<'a> Fn(RuntimeCallInfo<'a>, &mut [Fr]) -> eyre::Result<NativeRuntimeOutcome>
            + Send
            + Sync
            + 'static,
    ) -> Self {
        Self {
            matcher,
            function: Arc::new(function),
        }
    }

    pub fn matcher(&self) -> &RuntimeFunctionMatcher {
        &self.matcher
    }

    pub(crate) fn evaluate(
        &self,
        call: RuntimeCallInfo<'_>,
        outputs: &mut [Fr],
    ) -> eyre::Result<NativeRuntimeOutcome> {
        (self.function)(call, outputs)
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

/// Configuration for deterministic differential fuzzing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FuzzConfig {
    /// Number of random witnesses to compare.
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

/// Successful differential-fuzz run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FuzzReport {
    pub cases: usize,
    pub seed: u64,
}

/// Compares an original graph and a graph containing native replacements on random field inputs.
pub fn fuzz_equivalence(
    original: &Graph,
    optimized: &Graph,
    config: FuzzConfig,
    bbfs: Option<&std::collections::HashMap<String, BlackBoxFunction>>,
) -> eyre::Result<FuzzReport> {
    fuzz_equivalence_with(original, optimized, config, bbfs, |_, _| {})
}

/// Differential fuzzing with a hook for constraining generated inputs.
///
/// The hook runs after each input buffer is filled with random BN254 field elements. Position zero
/// is restored to one after the hook, matching [`crate::get_inputs_buffer`]. This is useful for
/// booleans, bounded integers, or other circuit-specific input domains.
pub fn fuzz_equivalence_with(
    original: &Graph,
    optimized: &Graph,
    config: FuzzConfig,
    bbfs: Option<&std::collections::HashMap<String, BlackBoxFunction>>,
    mut constrain: impl FnMut(usize, &mut [U256]),
) -> eyre::Result<FuzzReport> {
    let input_count = original.program.input_count();
    if optimized.program.input_count() != input_count {
        bail!(
            "cannot fuzz graphs with different input counts ({} and {})",
            input_count,
            optimized.program.input_count()
        );
    }

    let mut rng = StdRng::seed_from_u64(config.seed);
    let mut original_evaluator = original
        .evaluator(bbfs)
        .wrap_err("failed to prepare original graph")?;
    let mut optimized_evaluator = optimized
        .evaluator(bbfs)
        .wrap_err("failed to prepare optimized graph")?;
    let mut inputs = vec![U256::ZERO; input_count];

    for case in 0..config.cases {
        for input in &mut inputs {
            *input = rng.gen::<U256>() % M;
        }
        constrain(case, &mut inputs);
        inputs[0] = U256::ONE;

        let expected = original_evaluator.evaluate(&inputs).wrap_err_with(|| {
            format!(
                "original graph failed for fuzz case {case}, seed {}",
                config.seed
            )
        })?;
        let actual = optimized_evaluator.evaluate(&inputs).wrap_err_with(|| {
            format!(
                "optimized graph failed for fuzz case {case}, seed {}",
                config.seed
            )
        })?;
        if expected != actual {
            let output = expected
                .iter()
                .zip(actual)
                .position(|(expected, actual)| expected != actual)
                .unwrap_or(expected.len().min(actual.len()));
            let expected_value = expected.get(output);
            let actual_value = actual.get(output);
            return Err(eyre!(
                "witness mismatch at output {output} in fuzz case {case}, seed {} (expected {expected_value:?}, got {actual_value:?}); inputs: {inputs:?}",
                config.seed,
            ));
        }
    }

    Ok(FuzzReport {
        cases: config.cases,
        seed: config.seed,
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
        let report = fuzz_equivalence(
            &original,
            &optimized,
            FuzzConfig { cases: 32, seed: 7 },
            None,
        )
        .unwrap();
        assert_eq!(report.cases, 32);
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
    fn differential_fuzzer_reports_reproducible_mismatches() {
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
        let error = fuzz_equivalence(
            &original,
            &optimized,
            FuzzConfig { cases: 1, seed: 9 },
            None,
        )
        .unwrap_err();
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
        let handler = NativeRuntimeFunction::new(
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
        let optimized = original
            .customizer()
            .runtime_function(fallback)
            .runtime_function(handler)
            .build()
            .unwrap();

        fuzz_equivalence(
            &original,
            &optimized,
            FuzzConfig { cases: 8, seed: 11 },
            None,
        )
        .unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 8);
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

        fuzz_equivalence(
            &original,
            &optimized,
            FuzzConfig { cases: 8, seed: 12 },
            None,
        )
        .unwrap();
    }
}
