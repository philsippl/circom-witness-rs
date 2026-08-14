// SPDX-License-Identifier: GPL-3.0-only

use std::{env, path::PathBuf};

use circom_witness_graph_builder::generate_witness_graph_from_file_with_optimization;
use eyre::{eyre, Context as _};

fn main() -> eyre::Result<()> {
    let mut arguments = env::args_os().skip(1).collect::<Vec<_>>();
    let use_o1 = if arguments.first().is_some_and(|argument| argument == "--O1") {
        arguments.remove(0);
        true
    } else {
        if arguments.first().is_some_and(|argument| argument == "--O2") {
            arguments.remove(0);
        }
        false
    };
    let mut arguments = arguments.into_iter();
    let circuit = arguments.next().map(PathBuf::from).ok_or_else(|| {
        eyre!("usage: circom-witness-graph-builder <circuit> [output] [library paths...]")
    })?;
    let output = arguments
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("graph.bin"));
    let library_paths = arguments.map(PathBuf::from).collect::<Vec<_>>();

    let graph =
        generate_witness_graph_from_file_with_optimization(&circuit, &library_paths, use_o1)?;
    std::fs::write(&output, graph)
        .wrap_err_with(|| format!("failed to write graph to {}", output.display()))?;
    Ok(())
}
