//! Example circuit-specific extension for Semaphore's repeated Merkle-tree multiplexers.
//!
//! Run with a Semaphore graph built by `circom-witness-graph-builder`:
//!
//! ```text
//! cargo run --release --example semaphore -- semaphore.bin --record-fuzz-corpus corpus.json
//! cargo run --release --example semaphore -- semaphore.bin --fuzz-corpus corpus.json
//! ```

use std::{collections::BTreeMap, env, fs};

use circom_witness_rs::{
    custom::{record_fuzz_corpus, verify_fuzz_corpus, FuzzConfig, FuzzCorpus, NativeSubgraph},
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
    let mut arguments = env::args_os().skip(1);
    let path = arguments.next().ok_or_else(|| {
        eyre::eyre!(
            "usage: semaphore <semaphore-graph.bin> \
             (--record-fuzz-corpus CORPUS.json | --fuzz-corpus CORPUS.json)"
        )
    })?;
    let mode = arguments.next().and_then(|value| value.into_string().ok());
    let corpus_path = arguments.next();
    if arguments.next().is_some()
        || corpus_path.is_none()
        || !matches!(
            mode.as_deref(),
            Some("--record-fuzz-corpus" | "--fuzz-corpus")
        )
    {
        bail!(
            "usage: semaphore <semaphore-graph.bin> \
             (--record-fuzz-corpus CORPUS.json | --fuzz-corpus CORPUS.json)"
        );
    }
    let corpus_path = corpus_path.unwrap();
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
    let corpus = if mode.as_deref() == Some("--record-fuzz-corpus") {
        let corpus = record_fuzz_corpus(&original, FuzzConfig::default(), None)?;
        fs::write(&corpus_path, serde_json::to_vec_pretty(&corpus)?)
            .wrap_err("failed to write fuzz corpus")?;
        corpus
    } else {
        serde_json::from_slice::<FuzzCorpus>(
            &fs::read(&corpus_path).wrap_err("failed to read fuzz corpus")?,
        )
        .wrap_err("failed to decode fuzz corpus")?
    };
    let report = verify_fuzz_corpus(&optimized, &corpus, None)?;
    println!(
        "replaced {} mux pairs; {} pregenerated random witnesses matched",
        replacement_count, report.cases
    );
    println!(
        "runtime instructions: {} -> {}",
        original.runtime_instruction_count(),
        optimized.runtime_instruction_count()
    );
    Ok(())
}
