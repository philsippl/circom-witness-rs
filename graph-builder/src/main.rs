// SPDX-License-Identifier: GPL-3.0-only

use std::{env, path::PathBuf};

use circom_witness_graph_builder::generate_witness_graph_from_file;
use eyre::{eyre, Context as _};

fn main() -> eyre::Result<()> {
    let mut arguments = env::args_os().skip(1);
    let circuit = arguments.next().map(PathBuf::from).ok_or_else(|| {
        eyre!("usage: circom-witness-graph-builder <circuit> [output] [library paths...]")
    })?;
    let output = arguments
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("graph.bin"));
    let library_paths = arguments.map(PathBuf::from).collect::<Vec<_>>();

    let graph = generate_witness_graph_from_file(&circuit, &library_paths)?;
    std::fs::write(&output, graph)
        .wrap_err_with(|| format!("failed to write graph to {}", output.display()))?;
    Ok(())
}
