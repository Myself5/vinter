use std::fs::File;
use std::io::{BufReader, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde::Serialize;

use vinter_trace2img::{
    CrashImageGenerator, GenericCrashImageGenerator, LineGranularity, MemoryImage, MemoryImageMmap,
    MemoryReplayer, X86PersistentMemory,
};

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Process a trace and write the resulting PMEM contents to a file.
    ProcessTrace {
        /// size of PMEM area
        #[clap(long)]
        pmem_len: usize,
        /// include unpersisted lines in output
        #[clap(long)]
        include_unpersisted: bool,
        /// trace file to process (from vinter_trace)
        #[clap(parse(from_os_str))]
        trace: PathBuf,
        /// output file for PMEM contents
        #[clap(parse(from_os_str))]
        output: PathBuf,
    },

    /// Analyze a program based on a VM definition YAML file.
    Analyze {
        /// Path to VM definition YAML
        #[clap(parse(from_os_str))]
        vm_config: PathBuf,
        /// Path to test definition YAML
        #[clap(parse(from_os_str))]
        test_config: PathBuf,
        /// Path to output directory. Default "."
        #[clap(long, parse(from_os_str))]
        output_dir: Option<PathBuf>,
        #[clap(short, long)]
        /// Generator heuristic used to generate crash images. Options: (n)one, (d)efault, (f)pt.
        generator: Option<String>,
        #[clap(short, long)]
        /// Create a JSON output instead of the default, human readable text
        json: bool,
    },
}

#[derive(Debug, Serialize)]
struct JSONData {
    vm: String,
    test: String,
    heuristic: String,
    fences: usize,
    crash_images: usize,
    semantic_states: usize,
    failed_recovery_count: usize,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::ProcessTrace {
            pmem_len,
            include_unpersisted,
            trace,
            output,
        } => {
            let image = MemoryImageMmap::new(pmem_len)?;
            let mem = X86PersistentMemory::new(image, LineGranularity::Word)?;
            let mut replayer = MemoryReplayer::new(mem);
            let f = File::open(trace).context("could not open trace file")?;
            let mut reader = BufReader::new(f);
            for entry in replayer.process_trace(&mut reader) {
                entry?;
            }
            let mut mem = replayer.mem.borrow_mut();
            mem.print_unpersisted();
            if include_unpersisted {
                mem.persist_unpersisted();
            }
            let mut out = File::create(output).context("could not create output file")?;
            out.write(mem.memory_content())
                .context("could not write output file")?;
        }
        Commands::Analyze {
            vm_config,
            test_config,
            output_dir,
            generator,
            json,
        } => {
            let mut gen_config = CrashImageGenerator::Heuristic;
            let mut fences_log_text = "fences";
            if let Some(gen) = generator {
                match &gen[..] {
                    "n" | "none" => {
                        gen_config = CrashImageGenerator::None;
                    }
                    "d" | "default" => {
                        gen_config = CrashImageGenerator::Heuristic;
                    }
                    "f" | "fpt" => {
                        gen_config = CrashImageGenerator::FailurePointTree;
                        fences_log_text = "fences and flushes";
                    }
                    _ => {
                        println!("Invalid generator specified. Supported options: (n)one, (d)efault, (f)pt");
                        return Ok(());
                    }
                }
            }

            let vm = vm_config.file_stem().unwrap().to_str().unwrap().to_string();
            let test = test_config
                .file_stem()
                .unwrap()
                .to_str()
                .unwrap()
                .to_string();
            let gen_config_name = gen_config.to_string();

            let mut gen = GenericCrashImageGenerator::new(
                vm_config,
                test_config,
                output_dir.unwrap_or(PathBuf::from(".")),
                gen_config,
                json,
            )?;

            if !json {
                println!("Tracing command...");
            }
            gen.trace_pre_failure()
                .context("pre-failure tracing failed")?;
            if !json {
                println!("Pre-failure trace finished. Replaying trace...");
            }
            let fences_with_writes = gen.replay().context("replay failed")?;
            if !json {
                println!(
                    "Replay finished. {} {} with writes, {} crash images",
                    fences_with_writes,
                    fences_log_text,
                    gen.crash_images.len()
                );
                println!("Extracing semantic states...");
            }
            gen.extract_semantic_states()
                .context("semantic state extraction failed")?;
            if !json {
                println!(
                    "State extraction finished. {} unique states, {} failed recovery attempts",
                    gen.semantic_states.len(),
                    gen.get_failed_recovery_count(),
                );
            } else {
                let json = JSONData {
                    vm,
                    test,
                    heuristic: gen_config_name,
                    fences: fences_with_writes,
                    crash_images: gen.crash_images.len(),
                    semantic_states: gen.semantic_states.len(),
                    failed_recovery_count: gen.get_failed_recovery_count(),
                };
                let serialized_json = serde_json::to_string(&json).unwrap();
                println!("{}", serialized_json);
            }
        }
    }
    Ok(())
}
