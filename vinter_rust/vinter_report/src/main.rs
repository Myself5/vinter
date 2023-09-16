use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

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
    }
    Ok(())
}
