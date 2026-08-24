//! Deterministic benchmark summaries and flamegraph-like execution profiles.

use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

use eyre::{bail, Context as _};
use ruint::aliases::U256;
use serde::{Deserialize, Serialize};

use crate::{BlackBoxFunction, Graph};

/// Controls steady-state benchmarking and instrumented trace collection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileConfig {
    /// Unmeasured evaluations used to warm caches and reusable workspaces.
    pub warmup_iterations: usize,
    /// Uninstrumented evaluations used for trustworthy latency statistics.
    pub benchmark_iterations: usize,
    /// Separately instrumented evaluations used to attribute time to stack paths.
    pub trace_iterations: usize,
    /// Number of ordinary compact instructions timed as one low-overhead range.
    pub instruction_block_size: usize,
    /// Maximum entries retained in each ranked hotspot list. Zero retains every entry.
    pub max_hotspots: usize,
}

impl Default for ProfileConfig {
    fn default() -> Self {
        Self {
            warmup_iterations: 3,
            benchmark_iterations: 20,
            trace_iterations: 1,
            instruction_block_size: 128,
            max_hotspots: 50,
        }
    }
}

/// Stable category for one frame in a profile stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileFrameKind {
    Witness,
    InstructionBlock,
    Instruction,
    DivisionBatch,
    RuntimeFunction,
    NativeRuntimeHandler,
}

/// One structured segment in a flamegraph-like stack.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProfileFrame {
    pub kind: ProfileFrameKind,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instruction_start: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instruction_end: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_id: Option<usize>,
}

impl ProfileFrame {
    pub(crate) fn witness() -> Self {
        Self {
            kind: ProfileFrameKind::Witness,
            label: "witness".to_owned(),
            instruction_start: None,
            instruction_end: None,
            function_id: None,
        }
    }

    pub(crate) fn instruction(index: usize, label: impl Into<String>) -> Self {
        Self {
            kind: ProfileFrameKind::Instruction,
            label: label.into(),
            instruction_start: Some(index),
            instruction_end: Some(index + 1),
            function_id: None,
        }
    }

    pub(crate) fn instruction_block(start: usize, end: usize) -> Self {
        Self {
            kind: ProfileFrameKind::InstructionBlock,
            label: format!("instruction_block[{start}..{end}]"),
            instruction_start: Some(start),
            instruction_end: Some(end),
            function_id: None,
        }
    }

    pub(crate) fn division_batch(start: usize, end: usize) -> Self {
        Self {
            kind: ProfileFrameKind::DivisionBatch,
            label: format!("division_batch[{start}..{end}]"),
            instruction_start: Some(start),
            instruction_end: Some(end),
            function_id: None,
        }
    }

    pub(crate) fn runtime_function(function_id: usize, name: &str) -> Self {
        Self {
            kind: ProfileFrameKind::RuntimeFunction,
            label: format!("runtime[{function_id}]:{name}"),
            instruction_start: None,
            instruction_end: None,
            function_id: Some(function_id),
        }
    }

    pub(crate) fn native_runtime_handler(label: String) -> Self {
        Self {
            kind: ProfileFrameKind::NativeRuntimeHandler,
            label,
            instruction_start: None,
            instruction_end: None,
            function_id: None,
        }
    }
}

/// Steady-state latency summary collected without per-frame instrumentation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkSummary {
    pub warmup_iterations: usize,
    pub iterations: usize,
    pub total_ns: u64,
    pub mean_ns: u64,
    pub min_ns: u64,
    pub p50_ns: u64,
    pub p95_ns: u64,
    pub max_ns: u64,
}

/// Static count of compact instructions grouped by stable operation label.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstructionCount {
    pub operation: String,
    pub count: usize,
}

/// Half-open range of public [`Graph::nodes`](crate::Graph::nodes) IDs.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SourceNodeRange {
    pub start: usize,
    pub end: usize,
}

/// Aggregated timings for one exact stack path.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProfileEntry {
    pub stack: Vec<ProfileFrame>,
    pub calls: u64,
    pub inclusive_ns: u64,
    pub self_ns: u64,
    pub inclusive_percent: f64,
    pub self_percent: f64,
    /// Graph nodes represented by the leaf compact-instruction range, when available.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_node_ranges: Vec<SourceNodeRange>,
}

/// One concrete occurrence of a repeated structural optimization candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuralOccurrence {
    pub root_instruction: usize,
    pub root_source_nodes: Vec<usize>,
    pub compact_instruction_count: usize,
    pub source_node_ranges: Vec<SourceNodeRange>,
    pub boundary_source_nodes: Vec<usize>,
}

/// Repeated compact-program shape ranked by estimated aggregate inclusive time.
///
/// Shapes stop at shared values, graph outputs, inputs, and constants. Consequently every
/// occurrence is a conservative single-output native-subgraph candidate rather than an arbitrary
/// overlapping expression. Timings are apportioned from measured instruction blocks.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StructuralHotspot {
    pub fingerprint: String,
    pub root_operation: String,
    pub occurrences: usize,
    pub compact_instructions_per_occurrence: usize,
    pub graph_nodes_per_occurrence: usize,
    pub boundary_values_per_occurrence: usize,
    pub total_unique_compact_instructions: usize,
    pub estimated_inclusive_ns: u64,
    pub estimated_inclusive_percent: f64,
    pub samples: Vec<StructuralOccurrence>,
}

/// A conventional collapsed-stack sample. `self_ns` is suitable as a flamegraph weight.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FoldedStack {
    pub stack: String,
    pub self_ns: u64,
}

/// Machine-readable benchmark and profile report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProfileReport {
    pub schema_version: u32,
    pub benchmark: BenchmarkSummary,
    pub trace_iterations: usize,
    pub instruction_block_size: usize,
    pub trace_total_ns: u64,
    pub instruction_count: usize,
    pub runtime_function_count: usize,
    pub witness_elements: usize,
    pub source_provenance_available: bool,
    pub instruction_mix: Vec<InstructionCount>,
    pub structural_hotspots: Vec<StructuralHotspot>,
    pub distinct_stack_paths: usize,
    pub top_by_self: Vec<ProfileEntry>,
    pub top_by_inclusive: Vec<ProfileEntry>,
    pub folded_stacks: Vec<FoldedStack>,
    pub timing_note: String,
}

impl ProfileReport {
    /// Stable pretty-printed JSON intended for tooling and LLM agents.
    pub fn to_json_pretty(&self) -> eyre::Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Compact line-oriented text where every hotspot line contains explicit key/value fields.
    pub fn to_llm_text(&self) -> String {
        let mut output = String::new();
        output.push_str(&format!(
            "PROFILE schema_version={} instruction_count={} runtime_function_count={} witness_elements={} source_provenance_available={}\n",
            self.schema_version,
            self.instruction_count,
            self.runtime_function_count,
            self.witness_elements,
            self.source_provenance_available
        ));
        output.push_str(&format!(
            "BENCHMARK warmup_iterations={} iterations={} total_ns={} mean_ns={} min_ns={} p50_ns={} p95_ns={} max_ns={}\n",
            self.benchmark.warmup_iterations,
            self.benchmark.iterations,
            self.benchmark.total_ns,
            self.benchmark.mean_ns,
            self.benchmark.min_ns,
            self.benchmark.p50_ns,
            self.benchmark.p95_ns,
            self.benchmark.max_ns
        ));
        output.push_str(&format!(
            "TRACE iterations={} instruction_block_size={} total_ns={} distinct_stack_paths={} note={}\n",
            self.trace_iterations,
            self.instruction_block_size,
            self.trace_total_ns,
            self.distinct_stack_paths,
            serde_json::to_string(&self.timing_note).expect("serializing a string cannot fail")
        ));
        for instruction in &self.instruction_mix {
            output.push_str(&format!(
                "MIX operation={} count={}\n",
                serde_json::to_string(&instruction.operation)
                    .expect("serializing an instruction label cannot fail"),
                instruction.count
            ));
        }
        for (rank, hotspot) in self.structural_hotspots.iter().enumerate() {
            output.push_str(&format!(
                "STRUCTURE rank={} fingerprint={} root_operation={} occurrences={} compact_instructions_per_occurrence={} graph_nodes_per_occurrence={} boundary_values_per_occurrence={} total_unique_compact_instructions={} estimated_inclusive_ns={} estimated_inclusive_percent={:.4} samples={}\n",
                rank + 1,
                serde_json::to_string(&hotspot.fingerprint)
                    .expect("serializing a structural fingerprint cannot fail"),
                serde_json::to_string(&hotspot.root_operation)
                    .expect("serializing an instruction label cannot fail"),
                hotspot.occurrences,
                hotspot.compact_instructions_per_occurrence,
                hotspot.graph_nodes_per_occurrence,
                hotspot.boundary_values_per_occurrence,
                hotspot.total_unique_compact_instructions,
                hotspot.estimated_inclusive_ns,
                hotspot.estimated_inclusive_percent,
                serde_json::to_string(&hotspot.samples)
                    .expect("serializing structural samples cannot fail")
            ));
        }
        append_entries(&mut output, "SELF", &self.top_by_self);
        append_entries(&mut output, "INCLUSIVE", &self.top_by_inclusive);
        output
    }

    /// Conventional semicolon-separated collapsed stacks weighted by self time in nanoseconds.
    pub fn to_folded_stacks(&self) -> String {
        let mut output = String::new();
        for sample in &self.folded_stacks {
            output.push_str(&sample.stack);
            output.push(' ');
            output.push_str(&sample.self_ns.to_string());
            output.push('\n');
        }
        output
    }
}

fn append_entries(output: &mut String, prefix: &str, entries: &[ProfileEntry]) {
    for (rank, entry) in entries.iter().enumerate() {
        let path = entry
            .stack
            .iter()
            .map(|frame| frame.label.as_str())
            .collect::<Vec<_>>();
        output.push_str(&format!(
            "{prefix} rank={} calls={} self_ns={} self_percent={:.4} inclusive_ns={} inclusive_percent={:.4} source_node_ranges={} path={}\n",
            rank + 1,
            entry.calls,
            entry.self_ns,
            entry.self_percent,
            entry.inclusive_ns,
            entry.inclusive_percent,
            serde_json::to_string(&entry.source_node_ranges)
                .expect("serializing source node ranges cannot fail"),
            serde_json::to_string(&path).expect("serializing profile labels cannot fail")
        ));
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct Aggregate {
    calls: u64,
    inclusive_ns: u64,
    self_ns: u64,
}

struct ActiveFrame {
    frame: ProfileFrame,
    started: Instant,
    child_ns: u64,
}

#[derive(Default)]
pub(crate) struct ProfileCollector {
    active: Vec<ActiveFrame>,
    aggregates: BTreeMap<Vec<ProfileFrame>, Aggregate>,
    instruction_block_size: usize,
}

impl ProfileCollector {
    fn new(instruction_block_size: usize) -> Self {
        Self {
            instruction_block_size,
            ..Self::default()
        }
    }

    pub(crate) fn instruction_block_size(&self) -> usize {
        self.instruction_block_size.max(1)
    }

    pub(crate) fn enter(&mut self, frame: ProfileFrame) -> usize {
        let token = self.active.len();
        self.active.push(ActiveFrame {
            frame,
            started: Instant::now(),
            child_ns: 0,
        });
        token
    }

    pub(crate) fn exit(&mut self, token: usize) {
        debug_assert_eq!(token + 1, self.active.len());
        let active = self.active.pop().expect("profile frame stack is balanced");
        let inclusive_ns = duration_ns(active.started.elapsed());
        let self_ns = inclusive_ns.saturating_sub(active.child_ns);
        let mut path = self
            .active
            .iter()
            .map(|active| active.frame.clone())
            .collect::<Vec<_>>();
        path.push(active.frame);
        let aggregate = self.aggregates.entry(path).or_default();
        aggregate.calls = aggregate.calls.saturating_add(1);
        aggregate.inclusive_ns = aggregate.inclusive_ns.saturating_add(inclusive_ns);
        aggregate.self_ns = aggregate.self_ns.saturating_add(self_ns);
        if let Some(parent) = self.active.last_mut() {
            parent.child_ns = parent.child_ns.saturating_add(inclusive_ns);
        }
    }

    fn instruction_costs(&self, instruction_count: usize) -> Vec<u64> {
        let mut costs = vec![0_u64; instruction_count];
        for (stack, aggregate) in &self.aggregates {
            let Some(frame) = stack.last() else {
                continue;
            };
            if !matches!(
                frame.kind,
                ProfileFrameKind::InstructionBlock
                    | ProfileFrameKind::Instruction
                    | ProfileFrameKind::DivisionBatch
            ) {
                continue;
            }
            let (Some(start), Some(end)) = (frame.instruction_start, frame.instruction_end) else {
                continue;
            };
            let end = end.min(instruction_count);
            if start >= end {
                continue;
            }
            let width = (end - start) as u64;
            let quotient = aggregate.inclusive_ns / width;
            let remainder = aggregate.inclusive_ns % width;
            for (offset, cost) in costs[start..end].iter_mut().enumerate() {
                *cost = cost.saturating_add(quotient + u64::from((offset as u64) < remainder));
            }
        }
        costs
    }

    fn finish(
        self,
        benchmark: BenchmarkSummary,
        config: ProfileConfig,
        program: &crate::program::Program,
        witness_elements: usize,
        instruction_mix: Vec<InstructionCount>,
    ) -> ProfileReport {
        debug_assert!(self.active.is_empty());
        let trace_total_ns = self
            .aggregates
            .iter()
            .find_map(|(stack, aggregate)| {
                (stack.len() == 1 && stack[0].kind == ProfileFrameKind::Witness)
                    .then_some(aggregate.inclusive_ns)
            })
            .unwrap_or(0);
        let instruction_costs = self.instruction_costs(program.instruction_count());
        let structural_hotspots =
            program.structural_hotspots(&instruction_costs, trace_total_ns, config.max_hotspots);
        let denominator = trace_total_ns.max(1) as f64;
        let mut entries = self
            .aggregates
            .into_iter()
            .filter(|(stack, _)| !(stack.len() == 1 && stack[0].kind == ProfileFrameKind::Witness))
            .map(|(stack, aggregate)| {
                let source_node_ranges = stack
                    .last()
                    .and_then(|frame| Some((frame.instruction_start?, frame.instruction_end?)))
                    .map_or_else(Vec::new, |(start, end)| {
                        program.source_node_ranges(start..end)
                    });
                ProfileEntry {
                    stack,
                    calls: aggregate.calls,
                    inclusive_ns: aggregate.inclusive_ns,
                    self_ns: aggregate.self_ns,
                    inclusive_percent: aggregate.inclusive_ns as f64 * 100.0 / denominator,
                    self_percent: aggregate.self_ns as f64 * 100.0 / denominator,
                    source_node_ranges,
                }
            })
            .collect::<Vec<_>>();
        let distinct_stack_paths = entries.len();

        let mut top_by_self = entries.clone();
        top_by_self.sort_by(|left, right| {
            right
                .self_ns
                .cmp(&left.self_ns)
                .then_with(|| right.inclusive_ns.cmp(&left.inclusive_ns))
                .then_with(|| left.stack.cmp(&right.stack))
        });
        truncate(&mut top_by_self, config.max_hotspots);

        entries.sort_by(|left, right| {
            right
                .inclusive_ns
                .cmp(&left.inclusive_ns)
                .then_with(|| right.self_ns.cmp(&left.self_ns))
                .then_with(|| left.stack.cmp(&right.stack))
        });
        let mut top_by_inclusive = entries;
        truncate(&mut top_by_inclusive, config.max_hotspots);

        let folded_stacks = top_by_self
            .iter()
            .filter(|entry| entry.self_ns != 0)
            .map(|entry| FoldedStack {
                stack: entry
                    .stack
                    .iter()
                    .map(|frame| sanitize_folded_label(&frame.label))
                    .collect::<Vec<_>>()
                    .join(";"),
                self_ns: entry.self_ns,
            })
            .collect();

        ProfileReport {
            schema_version: 2,
            benchmark,
            trace_iterations: config.trace_iterations,
            instruction_block_size: config.instruction_block_size,
            trace_total_ns,
            instruction_count: program.instruction_count(),
            runtime_function_count: program.runtime_functions().len(),
            witness_elements,
            source_provenance_available: program.has_source_provenance(),
            instruction_mix,
            structural_hotspots,
            distinct_stack_paths,
            top_by_self,
            top_by_inclusive,
            folded_stacks,
            timing_note: "benchmark latency is uninstrumented; hotspot timings come from a separate instrumented trace and include profiling overhead; STRUCTURE timings are estimates apportioned from measured instruction ranges and may overlap across nested shapes".to_owned(),
        }
    }
}

fn truncate(entries: &mut Vec<ProfileEntry>, maximum: usize) {
    if maximum != 0 {
        entries.truncate(maximum);
    }
}

fn sanitize_folded_label(label: &str) -> String {
    label
        .chars()
        .map(|character| {
            if character == ';' || character.is_whitespace() {
                '_'
            } else {
                character
            }
        })
        .collect()
}

fn duration_ns(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

fn benchmark_summary(config: ProfileConfig, mut samples: Vec<u64>) -> BenchmarkSummary {
    samples.sort_unstable();
    let total = samples
        .iter()
        .fold(0_u64, |total, sample| total.saturating_add(*sample));
    let percentile = |percent: usize| samples[(samples.len() - 1) * percent / 100];
    BenchmarkSummary {
        warmup_iterations: config.warmup_iterations,
        iterations: config.benchmark_iterations,
        total_ns: total,
        mean_ns: total / config.benchmark_iterations as u64,
        min_ns: samples[0],
        p50_ns: percentile(50),
        p95_ns: percentile(95),
        max_ns: *samples.last().unwrap(),
    }
}

/// Benchmarks a graph and separately records a flamegraph-like execution trace.
///
/// The same stateful evaluator is reused for warmup, benchmark, and trace iterations. This measures
/// the normal steady-state API and excludes graph loading and callback binding.
pub fn profile_graph(
    graph: &Graph,
    inputs: &[U256],
    bbfs: Option<&std::collections::HashMap<String, BlackBoxFunction>>,
    config: ProfileConfig,
) -> eyre::Result<ProfileReport> {
    if config.benchmark_iterations == 0 {
        bail!("profile benchmark_iterations must be greater than zero");
    }
    if config.trace_iterations == 0 {
        bail!("profile trace_iterations must be greater than zero");
    }
    if config.instruction_block_size == 0 {
        bail!("profile instruction_block_size must be greater than zero");
    }

    graph
        .program
        .ensure_compatibility_source_map()
        .wrap_err("failed to prepare graph profiling provenance")?;

    let mut evaluator = graph
        .evaluator(bbfs)
        .wrap_err("failed to prepare graph profiler")?;
    let mut witness_elements = 0;
    for _ in 0..config.warmup_iterations {
        witness_elements = evaluator.evaluate(inputs)?.len();
    }

    let mut samples = Vec::with_capacity(config.benchmark_iterations);
    for _ in 0..config.benchmark_iterations {
        let started = Instant::now();
        witness_elements = evaluator.evaluate(inputs)?.len();
        samples.push(duration_ns(started.elapsed()));
        std::hint::black_box(witness_elements);
    }
    let benchmark = benchmark_summary(config, samples);

    let mut collector = ProfileCollector::new(config.instruction_block_size);
    for _ in 0..config.trace_iterations {
        let root = collector.enter(ProfileFrame::witness());
        let result = evaluator.evaluate_profiled(inputs, &mut collector);
        if result.is_ok() {
            collector.exit(root);
        }
        witness_elements = result?.len();
    }

    Ok(collector.finish(
        benchmark,
        config,
        &graph.program,
        witness_elements,
        graph
            .program
            .instruction_mix()
            .into_iter()
            .map(|(operation, count)| InstructionCount { operation, count })
            .collect(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        graph::{Node, Operation},
        init_graph,
        runtime::{RuntimeExpression, RuntimeFunction, RuntimeStatement},
        serialize_graph_with_runtime,
    };
    use serde_json::Value;

    fn load(offset: usize) -> RuntimeExpression {
        RuntimeExpression::Load {
            offset: Box::new(RuntimeExpression::Address(offset)),
            size: 1,
        }
    }

    fn nested_runtime_graph() -> Graph {
        let functions = vec![
            RuntimeFunction {
                name: "inner_3".to_owned(),
                variable_count: 1,
                body: vec![RuntimeStatement::Return {
                    value: load(0),
                    size: 1,
                }],
            },
            RuntimeFunction {
                name: "outer".to_owned(),
                variable_count: 1,
                body: vec![RuntimeStatement::Return {
                    value: RuntimeExpression::Call {
                        function: 0,
                        arena_size: 1,
                        result_size: 1,
                        arguments: vec![(load(0), 1)],
                    },
                    size: 1,
                }],
            },
        ];
        let nodes = vec![
            Node::Input(0),
            Node::RuntimeCall {
                function: 1,
                call: 0,
                output: 0,
                output_count: 1,
                arena_size: 1,
                argument_sizes: vec![1],
                parameters: vec![0],
            },
        ];
        init_graph(&serialize_graph_with_runtime(nodes, vec![1], Vec::new(), functions).unwrap())
            .unwrap()
    }

    #[test]
    fn profile_report_preserves_nested_runtime_stack_paths() {
        let graph = nested_runtime_graph();
        assert!(!graph.program.has_source_provenance());
        let report = profile_graph(
            &graph,
            &[U256::from(7_u64)],
            None,
            ProfileConfig {
                warmup_iterations: 0,
                benchmark_iterations: 2,
                trace_iterations: 2,
                instruction_block_size: 4,
                max_hotspots: 100,
            },
        )
        .unwrap();

        assert!(graph.program.has_source_provenance());
        assert_eq!(report.schema_version, 2);
        assert_eq!(report.benchmark.iterations, 2);
        assert_eq!(report.witness_elements, 1);
        let nested = report.top_by_inclusive.iter().find(|entry| {
            let labels = entry
                .stack
                .iter()
                .map(|frame| frame.label.as_str())
                .collect::<Vec<_>>();
            labels
                .iter()
                .any(|label| label.contains("runtime[1]:outer"))
                && labels
                    .iter()
                    .any(|label| label.contains("runtime[0]:inner_3"))
        });
        assert_eq!(nested.unwrap().calls, 2);
        assert!(report.to_llm_text().contains("INCLUSIVE rank="));
        let json = report.to_json_pretty().unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&json).unwrap()["schema_version"],
            2
        );
    }

    #[test]
    fn profile_report_maps_repeated_shapes_to_public_graph_nodes() {
        let nodes = vec![
            Node::Input(0),
            Node::Input(1),
            Node::Input(2),
            Node::Op(Operation::Sub, 0, 1),
            Node::Op(Operation::Mul, 3, 2),
            Node::Op(Operation::Add, 4, 1),
            Node::Op(Operation::Sub, 1, 0),
            Node::Op(Operation::Mul, 6, 2),
            Node::Op(Operation::Add, 7, 0),
        ];
        let graph =
            init_graph(&crate::serialize_graph(nodes, vec![5, 8], Vec::new()).unwrap()).unwrap();
        let report = profile_graph(
            &graph,
            &[U256::from(3_u64), U256::from(5_u64), U256::from(1_u64)],
            None,
            ProfileConfig {
                warmup_iterations: 0,
                benchmark_iterations: 1,
                trace_iterations: 1,
                instruction_block_size: 1,
                max_hotspots: 100,
            },
        )
        .unwrap();

        assert!(report.source_provenance_available);
        assert!(report
            .top_by_self
            .iter()
            .any(|entry| !entry.source_node_ranges.is_empty()));
        let repeated_mux = report
            .structural_hotspots
            .iter()
            .find(|hotspot| hotspot.root_operation == "add" && hotspot.occurrences == 2)
            .unwrap();
        assert_eq!(repeated_mux.compact_instructions_per_occurrence, 3);
        assert_eq!(repeated_mux.graph_nodes_per_occurrence, 3);
        assert_eq!(repeated_mux.samples.len(), 2);
        assert!(repeated_mux.samples.iter().all(|sample| {
            sample
                .source_node_ranges
                .iter()
                .all(|range| range.end <= graph.nodes().len())
        }));
        assert!(report.to_llm_text().contains("STRUCTURE rank="));
    }
}
