//! Example circuit-specific extension for Semaphore's repeated Merkle-tree multiplexers.
//!
//! Run with a Semaphore graph built by `circom-witness-graph-builder`:
//!
//! ```text
//! cargo run --release --example semaphore -- semaphore.bin
//! ```

use std::{collections::BTreeMap, env, fs};

use circom_witness_rs::{
    custom::{fuzz_equivalence, FuzzConfig, NativeSubgraph},
    graph::{Node, Operation},
    init_graph, Graph,
};
use eyre::{bail, Context as _};

fn mux_boundaries(nodes: &[Node], output: usize) -> Option<[usize; 3]> {
    let Node::Op(Operation::Add, left, right) = nodes[output] else {
        return None;
    };

    // Circom's MultiMux1 lowers `(one - zero) * selector + zero`. Accept commuted add and
    // multiplication operands because graph optimization may reorder either operation.
    for (scaled, zero) in [(left, right), (right, left)] {
        let Node::Op(Operation::Mul, mul_left, mul_right) = nodes[scaled] else {
            continue;
        };
        for (difference, selector) in [(mul_left, mul_right), (mul_right, mul_left)] {
            let Node::Op(Operation::Sub, one, subtracted_zero) = nodes[difference] else {
                continue;
            };
            if subtracted_zero == zero {
                return Some([one, zero, selector]);
            }
        }
    }
    None
}

fn semaphore_mux_replacements(graph: &Graph) -> Vec<NativeSubgraph> {
    let nodes = graph.nodes();
    let outputs = (0..nodes.len())
        .filter_map(|output| mux_boundaries(nodes, output).map(|boundary| (boundary, output)))
        .collect::<BTreeMap<_, _>>();
    let mut replacements = Vec::new();
    for (&[one, zero, selector], &forward) in &outputs {
        let Some(&reverse) = outputs.get(&[zero, one, selector]) else {
            continue;
        };
        if forward > reverse {
            continue;
        }
        replacements.push(NativeSubgraph::new(
            format!("semaphore-mux-pair-{forward}-{reverse}"),
            vec![one, zero, selector],
            vec![forward, reverse],
            |inputs, outputs| {
                outputs[0] = (inputs[0] - inputs[1]) * inputs[2] + inputs[1];
                outputs[1] = (inputs[1] - inputs[0]) * inputs[2] + inputs[0];
            },
        ));
    }
    replacements
}

fn main() -> eyre::Result<()> {
    let path = env::args_os()
        .nth(1)
        .ok_or_else(|| eyre::eyre!("usage: semaphore <semaphore-graph.bin>"))?;
    let bytes = fs::read(&path).wrap_err("failed to read Semaphore graph")?;
    let original = init_graph(&bytes).wrap_err("failed to load Semaphore graph")?;
    let replacements = semaphore_mux_replacements(&original);
    if replacements.is_empty() {
        bail!("no Semaphore MultiMux1 subgraphs were found");
    }

    let replacement_count = replacements.len();
    let optimized = original
        .customizer()
        .native_subgraphs(replacements)
        .build()?;
    let report = fuzz_equivalence(&original, &optimized, FuzzConfig::default(), None)?;
    println!(
        "replaced {} mux pairs; {} random witnesses matched (seed {})",
        replacement_count, report.cases, report.seed
    );
    println!(
        "runtime instructions: {} -> {}",
        original.runtime_instruction_count(),
        optimized.runtime_instruction_count()
    );
    Ok(())
}
