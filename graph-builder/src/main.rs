// SPDX-License-Identifier: GPL-3.0-only

use std::{env, path::PathBuf};

use circom_witness_graph_builder::{
    generate_witness_graph_from_file_with_options, GraphBuildOptions,
};
use eyre::{eyre, Context as _};

fn usage() -> &'static str {
    "usage: circom-witness-graph-builder [--O1|--O2] [--compression-level LEVEL] \
     <circuit> [output] [library paths...]"
}

fn main() -> eyre::Result<()> {
    let mut arguments = env::args_os().skip(1).peekable();
    let mut options = GraphBuildOptions::default();
    while let Some(argument) = arguments.peek().and_then(|argument| argument.to_str()) {
        match argument {
            "--O1" => {
                options.use_o1 = true;
                arguments.next();
            }
            "--O2" => {
                options.use_o1 = false;
                arguments.next();
            }
            "--compression-level" => {
                arguments.next();
                let level = arguments
                    .next()
                    .ok_or_else(|| eyre!("--compression-level requires a signed integer"))?;
                options.compression_level = level
                    .to_str()
                    .ok_or_else(|| eyre!("compression level is not valid UTF-8"))?
                    .parse()
                    .wrap_err("compression level must be a signed integer")?;
            }
            "--help" | "-h" => {
                println!("{}", usage());
                return Ok(());
            }
            flag if flag.starts_with('-') => return Err(eyre!("unknown option {flag:?}")),
            _ => break,
        }
    }
    let circuit = arguments
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| eyre!(usage()))?;
    let output = arguments
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("graph.bin"));
    let library_paths = arguments.map(PathBuf::from).collect::<Vec<_>>();

    let graph = generate_witness_graph_from_file_with_options(&circuit, &library_paths, options)?;
    std::fs::write(&output, graph)
        .wrap_err_with(|| format!("failed to write graph to {}", output.display()))?;
    Ok(())
}
