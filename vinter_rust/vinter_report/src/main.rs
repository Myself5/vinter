use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use serde::Serialize;

use vinter_common::Mmss;

use vinter_report::TraceAnalyzer;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Read a binary trace file and print a textual representation.
    ReadTrace {
        /// trace file to process (from vinter_trace)
        #[clap(parse(from_os_str))]
        trace: PathBuf,

        /// vmlinux file to resolve kernel symbols
        #[clap(long, parse(from_os_str))]
        vmlinux: Option<PathBuf>,

        /// how many entries to skip
        #[clap(long)]
        skip: Option<usize>,

        /// how many entries to show after start (does not account for filter)
        #[clap(long)]
        count: Option<usize>,

        /// comma seperated list of entries to filter. Options: all,read,write,fence,flush,hypercall
        #[clap(long)]
        filter: Option<String>,
    },

    // Analyze a given Trace file
    AnalyzeTrace {
        /// trace file to process (from vinter_trace)
        #[clap(parse(from_os_str))]
        trace: PathBuf,

        /// Path to output directory. Default "."
        #[clap(long, parse(from_os_str))]
        output_dir: Option<PathBuf>,

        #[clap(short, long)]
        /// Create a JSON output instead of the default, human readable text
        json: bool,
    },
}

#[derive(Debug, Serialize)]
struct TAJSONData {
    ta_bugs: usize,
    ta_entries: usize,
    total_ms: u128,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::ReadTrace {
            trace,
            vmlinux,
            skip,
            count,
            filter,
        } => {
            let ta = TraceAnalyzer::new();
            ta.read_trace(trace, vmlinux, filter, skip, count)?;
        }

        Commands::AnalyzeTrace {
            trace,
            output_dir,
            json,
        } => {
            let mut ta = TraceAnalyzer::new();
            if !json {
                println!("Analyzing Trace...");
            }
            let (ta_bugs, ta_entries) =
                ta.analyze_trace(trace, output_dir.unwrap_or(PathBuf::from(".")))?;

            let ta_data = TAJSONData {
                ta_bugs,
                ta_entries,
                total_ms: ta
                    .get_timing_end_trace_analysis()
                    .duration_since(ta.get_timing_start_trace_analysis())
                    .as_millis(),
            };

            if !json {
                println!(
                    "Found {} Trace Analysis Bugs out of {} entries in {}.",
                    ta_bugs,
                    ta_entries,
                    ta.get_timing_end_trace_analysis()
                        .duration_since(ta.get_timing_start_trace_analysis())
                        .mmss()
                );
            } else {
                let serialized_json = serde_json::to_string(&ta_data).unwrap();
                println!("{}", serialized_json);
            }
        }
    }
    Ok(())
}
