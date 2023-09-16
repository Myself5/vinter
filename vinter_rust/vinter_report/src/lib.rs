use anyhow::{Context, Result};
use std::io::{BufReader, Read};
use std::path::Path;
use std::{fs::File, path::PathBuf};

use vinter_common::trace::{self, TraceEntry};

pub struct TraceFilter {
    pub read: bool,
    pub write: bool,
    pub fence: bool,
    pub flush: bool,
    pub hypercall: bool,
}

impl TraceFilter {
    pub fn new(initial_value: bool) -> TraceFilter {
        TraceFilter {
            read: initial_value,
            write: initial_value,
            fence: initial_value,
            flush: initial_value,
            hypercall: initial_value,
        }
    }
    pub fn set_all(&mut self, new_value: bool) {
        self.read = new_value;
        self.write = new_value;
        self.fence = new_value;
        self.flush = new_value;
        self.hypercall = new_value;
    }
}

pub fn init_addr2line(vmlinux: &Path) -> Result<addr2line::ObjectContext> {
    let mut f = File::open(vmlinux).context("could not open vmlinux file")?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    let parsed = addr2line::object::read::File::parse(&*buf)?;
    Ok(addr2line::Context::new(&parsed)?)
}

pub fn print_frame(a2l: &addr2line::ObjectContext, addr: u64) {
    print!("0x{:x} ", addr);
    match a2l.find_frames(addr) {
        Ok(mut iter) => match iter.next() {
            Ok(Some(frame)) => {
                if let Some(function) = frame.function {
                    print!("{}", function.demangle().unwrap());
                } else {
                    print!("??");
                }
            }
            Ok(None) => {
                print!("??");
            }
            Err(err) => {
                print!("<frame error: {}>", err);
            }
        },
        Err(err) => {
            print!("<frame error: {}>", err);
        }
    }
    print!(" at ");
    match a2l.find_location(addr) {
        Ok(Some(loc)) => {
            println!(
                "{file}:{line}:{column}",
                file = loc.file.unwrap_or("?"),
                line = loc.line.unwrap_or(0),
                column = loc.column.unwrap_or(0)
            );
        }
        Ok(None) => {
            println!("?");
        }
        Err(err) => {
            println!("<location error: {}>", err);
        }
    }
}

macro_rules! print_kernel_stracktrace {
    ($metadata:expr; $a2l:expr) => {
        if let Some(a2l) = &$a2l {
            if $metadata.in_kernel {
                print!("\tpc: ");
                print_frame(a2l, $metadata.pc);
                if !$metadata.kernel_stacktrace.is_empty() {
                    println!("\tstack trace:");
                    for (i, addr) in $metadata.kernel_stacktrace.iter().enumerate() {
                        print!("\t#{}: ", i + 1);
                        print_frame(a2l, *addr);
                    }
                }
            }
        }
    };
}

pub struct TraceAnalyzer {}

impl TraceAnalyzer {
    pub fn new() -> TraceAnalyzer {
        TraceAnalyzer {}
    }
    pub fn read_trace(
        &self,
        trace: PathBuf,
        vmlinux: Option<PathBuf>,
        filter: Option<String>,
        skip: Option<usize>,
        count: Option<usize>,
    ) -> Result<()> {
        let trace_filter = if let Some(filter) = filter {
            let mut tf = TraceFilter::new(false);

            for entry in filter.split(",") {
                match entry {
                    "all" => {
                        tf.set_all(true);
                        break;
                    }
                    "read" => {
                        tf.read = true;
                    }
                    "write" => {
                        tf.write = true;
                    }
                    "fence" => {
                        tf.fence = true;
                    }
                    "flush" => {
                        tf.flush = true;
                    }
                    "hypercall" => {
                        tf.hypercall = true;
                    }
                    _ => {
                        println!("Unsupported filter: {}", entry);
                        return Ok(());
                    }
                }
            }

            tf
        } else {
            TraceFilter::new(true)
        };

        let a2l = if let Some(vmlinux) = vmlinux {
            Some(init_addr2line(&vmlinux)?)
        } else {
            None
        };
        let mut file = BufReader::new(File::open(&trace).context("could not open trace file")?);

        let max_count = if let Some(c) = count {
            if c == 0 {
                println!("Invalid parameter: --count 0 will be ignored.");
            }
            c
        } else {
            0
        };
        let mut current_count = 0;

        for entry in trace::parse_trace_file_bin(&mut file).skip(skip.unwrap_or(0)) {
            current_count += 1;
            if max_count > 0 && current_count > max_count {
                return Ok(());
            }

            let entry = entry?;

            match entry.clone() {
                TraceEntry::Write { metadata, .. } => {
                    if trace_filter.write {
                        println!("{:?}", entry);

                        print_kernel_stracktrace!(metadata; a2l);
                    }
                }
                TraceEntry::Fence { metadata, .. } => {
                    if trace_filter.fence {
                        println!("{:?}", entry);

                        print_kernel_stracktrace!(metadata; a2l);
                    }
                }
                TraceEntry::Flush { metadata, .. } => {
                    if trace_filter.flush {
                        println!("{:?}", entry);

                        print_kernel_stracktrace!(metadata; a2l);
                    }
                }
                TraceEntry::Read { .. } => {
                    if trace_filter.read {
                        println!("{:?}", entry);
                    }
                }
                TraceEntry::Hypercall { .. } => {
                    if trace_filter.hypercall {
                        println!("{:?}", entry);
                    }
                }
            }
        }

        Ok(())
    }
}
