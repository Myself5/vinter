use std::fs::File;
use std::io::{BufReader, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde::Serialize;

use vinter_common::Mmss;

use vinter_trace2img::{
    CrashImageGenerator, GenericCrashImageGenerator, LineGranularity, MemoryImage, MemoryImageMmap,
    MemoryReplayer, TraceAnalyzer, X86PersistentMemory,
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
        #[clap(short, long)]
        /// Show verbose duration timings (always included in json)
        verbose: bool,
        #[clap(short, long)]
        /// Use Advanced Trace analysis to find performance and implementation bugs
        trace_analysis: bool,
        #[clap(short, long)]
        /// Store the kernel stacktrace in the trace. Default: true when using trace analysis or the FPT heuristic, false otherwise
        kernel_stacktrace: bool,
    },
    // Analyze a given Trace file
    AnalyzeTrace {
        // Path to trace file
        #[clap(parse(from_os_str))]
        trace_file: PathBuf,
        /// Path to output directory. Default "."
        #[clap(long, parse(from_os_str))]
        output_dir: Option<PathBuf>,
        #[clap(short, long)]
        /// Create a JSON output instead of the default, human readable text
        json: bool,
    },
}

#[derive(Debug, Serialize)]
struct JSONData {
    vm: String,
    test: String,
    tech: String,
    fences: usize,
    crash_images: usize,
    semantic_states: usize,
    failed_recoveries: usize,
    ta_bugs: usize,
    ta_entries: usize,
    trace_ms: u128,
    crash_image_ms: u128,
    trace_analysis_ms: u128,
    semantic_state_ms: u128,
    total_ms: u128,
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
            verbose,
            trace_analysis,
            kernel_stacktrace,
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
            let mut tech_config = gen_config.to_string();
            if trace_analysis {
                tech_config.push_str("+TA");
            }

            let mut gen = GenericCrashImageGenerator::new(
                vm_config,
                test_config,
                output_dir.unwrap_or(PathBuf::from(".")),
                gen_config,
                json,
                trace_analysis || kernel_stacktrace,
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

            let mut ta_bugs = 0;
            let mut ta_entries = 0;
            let mut ta = TraceAnalyzer::new();
            if trace_analysis {
                if !json {
                    println!("Analyzing Trace...");
                }
                (ta_bugs, ta_entries) = ta.analyze_trace(gen.trace_path(), gen.get_output_dir())?;
            }

            if !json {
                if !trace_analysis {
                    println!(
                        "Replay finished. {} {} with writes, {} crash images",
                        fences_with_writes,
                        fences_log_text,
                        gen.crash_images.len()
                    );
                } else {
                    println!(
                    "Replay finished. {} {} with writes, {} crash images, {} trace analysis bugs",
                    fences_with_writes,
                    fences_log_text,
                    gen.crash_images.len(),
                    ta_bugs,
                );
                }
                println!("Extracing semantic states...");
            }
            gen.extract_semantic_states()
                .context("semantic state extraction failed")?;

            let json_data = JSONData {
                vm,
                test,
                tech: tech_config,
                fences: fences_with_writes,
                crash_images: gen.crash_images.len(),
                semantic_states: gen.semantic_states.len(),
                failed_recoveries: gen.get_failed_recovery_count(),
                ta_bugs,
                ta_entries,
                trace_ms: gen
                    .get_timing_start_crash_image_generation()
                    .duration_since(gen.get_timing_trace())
                    .as_millis(),
                crash_image_ms: if trace_analysis {
                    ta.get_timing_start_trace_analysis()
                } else {
                    gen.get_timing_start_semantic_state_generation()
                }
                .duration_since(gen.get_timing_start_crash_image_generation())
                .as_millis(),
                trace_analysis_ms: if trace_analysis {
                    ta.get_timing_end_trace_analysis()
                        .duration_since(ta.get_timing_start_trace_analysis())
                        .as_millis()
                } else {
                    0
                },
                semantic_state_ms: gen
                    .get_timing_end_semantic_state_generation()
                    .duration_since(if trace_analysis {
                        ta.get_timing_end_trace_analysis()
                    } else {
                        gen.get_timing_start_semantic_state_generation()
                    })
                    .as_millis(),
                total_ms: gen
                    .get_timing_end_semantic_state_generation()
                    .duration_since(gen.get_timing_trace())
                    .as_millis(),
            };

            let output_file = File::create(gen.get_output_dir().join("output.yaml"))?;
            serde_yaml::to_writer(&output_file, &json_data)
                .context("failed writing output.yaml")?;

            if !json {
                println!(
                    "State extraction finished. {} unique states, {} failed recovery attempts.",
                    gen.semantic_states.len(),
                    gen.get_failed_recovery_count(),
                );
                if verbose {
                    println!("Durations:");
                    println!(
                        "Trace: {}",
                        gen.get_timing_start_crash_image_generation()
                            .duration_since(gen.get_timing_trace())
                            .mmss(),
                    );
                    println!(
                        "Crash Image Generation: {}",
                        if trace_analysis {
                            ta.get_timing_start_trace_analysis()
                        } else {
                            gen.get_timing_start_semantic_state_generation()
                        }
                        .duration_since(gen.get_timing_start_crash_image_generation())
                        .mmss(),
                    );
                    if trace_analysis {
                        println!(
                            "Trace Analysis: {}",
                            ta.get_timing_end_trace_analysis()
                                .duration_since(ta.get_timing_start_trace_analysis())
                                .mmss(),
                        );
                    }
                    println!(
                        "Semantic State Extraction: {}",
                        gen.get_timing_end_semantic_state_generation()
                            .duration_since(if trace_analysis {
                                ta.get_timing_end_trace_analysis()
                            } else {
                                gen.get_timing_start_semantic_state_generation()
                            })
                            .mmss(),
                    );
                }
                println!(
                    "Total Duration: {}",
                    gen.get_timing_end_semantic_state_generation()
                        .duration_since(gen.get_timing_trace())
                        .mmss()
                );
            } else {
                let serialized_json = serde_json::to_string(&json_data).unwrap();
                println!("{}", serialized_json);
            }
        }
        Commands::AnalyzeTrace {
            trace_file,
            output_dir,
            json,
        } => {
            let mut ta = TraceAnalyzer::new();
            if !json {
                println!("Analyzing Trace...");
            }
            let (ta_bugs, ta_entries) =
                ta.analyze_trace(trace_file, output_dir.unwrap_or(PathBuf::from(".")))?;

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
