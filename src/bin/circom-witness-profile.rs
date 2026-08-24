use std::{
    collections::HashMap,
    env, fs,
    path::{Path, PathBuf},
};

use circom_witness_rs::{
    get_inputs_buffer, init_graph, populate_inputs,
    profile::{profile_graph, ProfileConfig},
    try_get_input_mapping,
};
use eyre::{bail, eyre, Context as _};
use ruint::aliases::U256;
use serde_json::Value;

#[derive(Clone, Copy)]
enum OutputFormat {
    Llm,
    Json,
    Folded,
}

struct Options {
    graph: PathBuf,
    inputs: PathBuf,
    output: Option<PathBuf>,
    format: OutputFormat,
    profile: ProfileConfig,
}

fn usage() -> &'static str {
    "usage: circom-witness-profile <graph.bin> <input.json> [options]\n\
     options:\n\
       --format llm|json|folded   output format (default: llm)\n\
       --warmup N                 unmeasured warmup iterations (default: 3)\n\
       --iterations N             uninstrumented benchmark iterations (default: 20)\n\
       --trace-iterations N       instrumented profile iterations (default: 1)\n\
       --block-size N             ordinary instructions per timed range (default: 128)\n\
       --top N                    hotspots retained per ranking; 0 means all (default: 50)\n\
       --output PATH              write output to a file instead of stdout"
}

fn parse_usize(flag: &str, value: Option<String>) -> eyre::Result<usize> {
    value
        .ok_or_else(|| eyre!("{flag} requires a value"))?
        .parse()
        .wrap_err_with(|| format!("invalid value for {flag}"))
}

fn parse_options() -> eyre::Result<Options> {
    let mut arguments = env::args().skip(1);
    let Some(graph) = arguments.next() else {
        bail!(usage());
    };
    if graph == "--help" || graph == "-h" {
        println!("{}", usage());
        std::process::exit(0);
    }
    let inputs = arguments.next().ok_or_else(|| eyre!(usage()))?;
    let mut options = Options {
        graph: graph.into(),
        inputs: inputs.into(),
        output: None,
        format: OutputFormat::Llm,
        profile: ProfileConfig::default(),
    };

    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--format" => {
                options.format = match arguments.next().as_deref() {
                    Some("llm") => OutputFormat::Llm,
                    Some("json") => OutputFormat::Json,
                    Some("folded") => OutputFormat::Folded,
                    Some(value) => bail!("unsupported profile format {value:?}"),
                    None => bail!("--format requires a value"),
                }
            }
            "--warmup" => {
                options.profile.warmup_iterations = parse_usize("--warmup", arguments.next())?;
            }
            "--iterations" => {
                options.profile.benchmark_iterations =
                    parse_usize("--iterations", arguments.next())?;
            }
            "--trace-iterations" => {
                options.profile.trace_iterations =
                    parse_usize("--trace-iterations", arguments.next())?;
            }
            "--block-size" => {
                options.profile.instruction_block_size =
                    parse_usize("--block-size", arguments.next())?;
            }
            "--top" => {
                options.profile.max_hotspots = parse_usize("--top", arguments.next())?;
            }
            "--output" => {
                options.output = Some(
                    arguments
                        .next()
                        .ok_or_else(|| eyre!("--output requires a path"))?
                        .into(),
                );
            }
            "--help" | "-h" => {
                println!("{}", usage());
                std::process::exit(0);
            }
            unknown => bail!("unknown option {unknown:?}\n{}", usage()),
        }
    }
    Ok(options)
}

fn flatten_value(value: Value, output: &mut Vec<U256>) -> eyre::Result<()> {
    match value {
        Value::Array(values) => {
            for value in values {
                flatten_value(value, output)?;
            }
        }
        value => output.push(
            serde_json::from_value(value).wrap_err("input is not a valid unsigned field value")?,
        ),
    }
    Ok(())
}

fn load_inputs(path: &Path) -> eyre::Result<HashMap<String, Vec<U256>>> {
    let bytes = fs::read(path)
        .wrap_err_with(|| format!("failed to read input JSON from {}", path.display()))?;
    let object = serde_json::from_slice::<Value>(&bytes)
        .wrap_err("failed to parse input JSON")?
        .as_object()
        .cloned()
        .ok_or_else(|| eyre!("input JSON must be an object keyed by Circom signal name"))?;
    object
        .into_iter()
        .map(|(name, value)| {
            let mut values = Vec::new();
            flatten_value(value, &mut values)?;
            Ok((name, values))
        })
        .collect()
}

fn main() -> eyre::Result<()> {
    let options = parse_options()?;
    let graph_bytes = fs::read(&options.graph)
        .wrap_err_with(|| format!("failed to read graph from {}", options.graph.display()))?;
    let graph = init_graph(&graph_bytes).wrap_err("failed to load witness graph")?;
    let inputs = load_inputs(&options.inputs)?;
    let input_names = inputs.keys().cloned().collect::<Vec<_>>();
    let input_mapping = try_get_input_mapping(&input_names, &graph)?;
    let mut input_buffer = get_inputs_buffer(circom_witness_rs::get_inputs_size(&graph));
    populate_inputs(&inputs, &input_mapping, &mut input_buffer);

    let report = profile_graph(&graph, &input_buffer, None, options.profile)?;
    let rendered = match options.format {
        OutputFormat::Llm => report.to_llm_text(),
        OutputFormat::Json => report.to_json_pretty()?,
        OutputFormat::Folded => report.to_folded_stacks(),
    };
    if let Some(output) = options.output {
        fs::write(&output, rendered)
            .wrap_err_with(|| format!("failed to write profile to {}", output.display()))?;
    } else {
        print!("{rendered}");
    }
    Ok(())
}
