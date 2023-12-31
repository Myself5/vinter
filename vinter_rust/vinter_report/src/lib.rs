use anyhow::{bail, Context, Result};

use std::collections::HashMap;
use std::fmt::Write;
use std::fs::File;
use std::io::{BufReader, Read, Write as IOWrite};
use std::path::{Path, PathBuf};
use std::time::Instant;

use vinter_common::fptree::FailurePointTree;
use vinter_common::trace::{self, TraceEntry};
use vinter_common::{Bug, BugType, FPTBug};

const CACHELINE_SIZE: usize = 64;

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

pub fn print_frame(a2l: &addr2line::ObjectContext, addr: u64) -> String {
    let mut output = String::new();
    write!(output, "0x{:x} ", addr).unwrap();
    match a2l.find_frames(addr) {
        Ok(mut iter) => match iter.next() {
            Ok(Some(frame)) => {
                if let Some(function) = frame.function {
                    write!(output, "{}", function.demangle().unwrap()).unwrap();
                } else {
                    write!(output, "??").unwrap();
                }
            }
            Ok(None) => {
                write!(output, "??").unwrap();
            }
            Err(err) => {
                write!(output, "<frame error: {}>", err).unwrap();
            }
        },
        Err(err) => {
            write!(output, "<frame error: {}>", err).unwrap();
        }
    }
    write!(output, " at ").unwrap();
    match a2l.find_location(addr) {
        Ok(Some(loc)) => {
            write!(
                output,
                "{file}:{line}:{column}\n",
                file = loc.file.unwrap_or("?"),
                line = loc.line.unwrap_or(0),
                column = loc.column.unwrap_or(0)
            )
            .unwrap();
        }
        Ok(None) => {
            write!(output, "?\n").unwrap();
        }
        Err(err) => {
            write!(output, "<location error: {}>\n", err).unwrap();
        }
    }

    output
}

macro_rules! get_kernel_stracktrace {
    ($metadata:expr; $a2l:expr; $output:expr; $padding:expr) => {
        if let Some(a2l) = &$a2l {
            if $metadata.in_kernel {
                write!(
                    $output,
                    "{}pc: {}",
                    $padding,
                    print_frame(a2l, $metadata.pc)
                )
                .unwrap();
                if !$metadata.kernel_stacktrace.is_empty() {
                    write!($output, "{}stack trace:\n", $padding).unwrap();
                    for (i, addr) in $metadata.kernel_stacktrace.iter().enumerate() {
                        write!(
                            $output,
                            "{}#{}: {}",
                            $padding,
                            i + 1,
                            print_frame(a2l, *addr)
                        )
                        .unwrap();
                    }
                }
            }
        }
    };
}

#[derive(PartialEq, Clone)]
enum StoreState {
    Modified,
    PartiallyFlushed,
    Flushed,
    // Fenced, // Unused, but included in the Mumak design
}

#[derive(Clone)]
struct Store {
    size: usize,
    instruction_id: usize,
    state: StoreState,
    checkpoint_id: isize,
    kernel_stacktrace: Vec<u64>,
}

impl Store {
    fn new(
        size: usize,
        instruction_id: usize,
        checkpoint_id: isize,
        kernel_stacktrace: Vec<u64>,
    ) -> Store {
        Store {
            size,
            instruction_id,
            state: StoreState::Modified,
            checkpoint_id,
            kernel_stacktrace,
        }
    }
    fn change_state(&mut self, new_state: StoreState) {
        self.state = new_state;
    }
}

pub struct TraceAnalyzer {
    fences_pending: HashMap<usize, Store>,
    flushes_pending: HashMap<usize, Store>,
    bugs: Vec<Bug>,
    unordered_flushes: Vec<usize>,
    timing_start_trace_analysis: Instant,
    timing_end_trace_analysis: Instant,
    failure_point_tree: FailurePointTree,
    trace_entries: HashMap<usize, TraceEntry>,
}

impl TraceAnalyzer {
    pub fn new() -> TraceAnalyzer {
        let mut failure_point_tree = FailurePointTree::new();
        failure_point_tree.set_trace_analysis(true);
        TraceAnalyzer {
            fences_pending: HashMap::new(),
            flushes_pending: HashMap::new(),
            bugs: Vec::new(),
            unordered_flushes: Vec::new(),
            timing_start_trace_analysis: Instant::now(),
            timing_end_trace_analysis: Instant::now(),
            failure_point_tree,
            trace_entries: HashMap::new(),
        }
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

                        let mut stacktrace = String::new();
                        get_kernel_stracktrace!(metadata; a2l; stacktrace; "\t");
                        print!("{}", stacktrace);
                    }
                }
                TraceEntry::Fence { metadata, .. } => {
                    if trace_filter.fence {
                        println!("{:?}", entry);

                        let mut stacktrace = String::new();
                        get_kernel_stracktrace!(metadata; a2l; stacktrace; "\t");
                        print!("{}", stacktrace);
                    }
                }
                TraceEntry::Flush { metadata, .. } => {
                    if trace_filter.flush {
                        println!("{:?}", entry);

                        let mut stacktrace = String::new();
                        get_kernel_stracktrace!(metadata; a2l; stacktrace; "\t");
                        print!("{}", stacktrace);
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

    fn target_store_contains_source_store(
        source_addr: usize,
        source_size: usize,
        target_addr: usize,
        target_size: usize,
    ) -> bool {
        (target_addr <= source_addr) && (target_size >= (source_addr + source_size))
    }

    fn source_store_contains_target_store(
        source_addr: usize,
        source_size: usize,
        target_addr: usize,
        target_size: usize,
    ) -> bool {
        (target_addr >= source_addr) && (target_size <= (source_addr + source_size))
    }

    fn store_is_partially_inside_cacheline_in_left(
        flush_addr: usize,
        flush_size: usize,
        store_addr: usize,
        store_size: usize,
    ) -> bool {
        (flush_addr > store_addr)
            && ((store_addr + store_size) > flush_addr)
            && ((flush_addr + flush_size) > (store_addr + store_size))
    }

    fn store_is_partially_inside_cacheline_in_right(
        flush_addr: usize,
        flush_size: usize,
        store_addr: usize,
        store_size: usize,
    ) -> bool {
        (flush_addr < store_addr)
            && ((flush_addr + flush_size) > store_addr)
            && ((flush_addr + flush_size) < (store_addr + store_size))
    }

    fn store_is_partially_inside_cacheline(
        flush_addr: usize,
        flush_size: usize,
        store_addr: usize,
        store_size: usize,
    ) -> bool {
        Self::store_is_partially_inside_cacheline_in_right(
            flush_addr, flush_size, store_addr, store_size,
        ) || Self::store_is_partially_inside_cacheline_in_left(
            flush_addr, flush_size, store_addr, store_size,
        )
    }

    fn store_is_inside_cacheline(
        flush_addr: usize,
        flush_size: usize,
        store_addr: usize,
        store_size: usize,
    ) -> bool {
        (store_addr >= flush_addr) && (store_addr + store_size <= flush_addr + flush_size)
    }

    pub fn analyze_trace(
        &mut self,
        trace_file: PathBuf,
        vmlinux: Option<PathBuf>,
        output_dir: Option<PathBuf>,
        verbose: bool,
    ) -> Result<(usize, usize)> {
        self.timing_start_trace_analysis = Instant::now();

        let mut ta_entries = 0;
        let mut pre_failure_success = false;
        let mut last_hypercall_checkpoint: isize = -1;
        let mut previous_checkpoints = Vec::new();

        let mut file =
            BufReader::new(File::open(&trace_file).context("could not open trace file")?);

        for entry in trace::parse_trace_file_bin(&mut file) {
            let entry = entry?;
            match entry.clone() {
                TraceEntry::Write {
                    id,
                    address,
                    size,
                    non_temporal,
                    metadata,
                    ..
                } => {
                    if last_hypercall_checkpoint >= 0 {
                        ta_entries += 1;
                        if metadata.kernel_stacktrace.is_empty() {
                            bail!("kernel_stacktrace is empty. Please regenerate trace with a kernel_stacktrace included.");
                        }
                        self.trace_entries.insert(id, entry);
                        self.process_trace_entry_write(
                            address,
                            size,
                            non_temporal,
                            id,
                            last_hypercall_checkpoint,
                            metadata.kernel_stacktrace,
                        );
                    }
                }
                TraceEntry::Fence { id, metadata, .. } => {
                    if last_hypercall_checkpoint >= 0 {
                        ta_entries += 1;
                        if metadata.kernel_stacktrace.is_empty() {
                            bail!("kernel_stacktrace is empty. Please regenerate trace with a kernel_stacktrace included.");
                        }
                        self.trace_entries.insert(id, entry);
                        self.process_trace_entry_fence(
                            id,
                            last_hypercall_checkpoint,
                            metadata.kernel_stacktrace,
                        );
                    }
                }
                TraceEntry::Flush {
                    id,
                    mnemonic,
                    address,
                    metadata,
                    ..
                } => {
                    if last_hypercall_checkpoint >= 0 {
                        ta_entries += 1;
                        if metadata.kernel_stacktrace.is_empty() {
                            bail!("kernel_stacktrace is empty. Please regenerate trace with a kernel_stacktrace included.");
                        }
                        self.trace_entries.insert(id, entry);
                        self.process_trace_entry_flush(
                            &mnemonic,
                            address,
                            id,
                            last_hypercall_checkpoint,
                            metadata.kernel_stacktrace,
                        );
                    }
                }
                TraceEntry::Hypercall {
                    id, action, value, ..
                } => match action.as_ref() {
                    "checkpoint" => {
                        if !pre_failure_success {
                            last_hypercall_checkpoint =
                                value.parse().context("invalid checkpoint value")?;
                            if previous_checkpoints.contains(&last_hypercall_checkpoint) {
                                bail!(
                                    "duplicate checkpoint id {} at trace_id {}",
                                    last_hypercall_checkpoint,
                                    id
                                );
                            } else {
                                previous_checkpoints.push(last_hypercall_checkpoint);
                            }
                        }
                    }
                    "success" => {
                        if pre_failure_success {
                            bail!("multiple success hypercalls");
                        }
                        pre_failure_success = true;
                    }
                    _ => {}
                },
                _ => (),
            }
        }

        self.check_remainder();

        let a2l = if let Some(vmlinux) = vmlinux {
            Some(init_addr2line(&vmlinux)?)
        } else {
            None
        };

        let mut formatted_output_string = String::new();

        for bug in &self.bugs {
            writeln!(formatted_output_string, "- Bug Type: {:?}", bug.bug_type).unwrap();
            writeln!(formatted_output_string, "  Checkpoint: {}", bug.checkpoint).unwrap();
            writeln!(formatted_output_string, "  Responsible Trace Entries:",).unwrap();
            for entry in &bug.trace_entries {
                match entry {
                    TraceEntry::Write { metadata, .. }
                    | TraceEntry::Fence { metadata, .. }
                    | TraceEntry::Flush { metadata, .. } => {
                        if verbose {
                            writeln!(formatted_output_string, "  - {:?}", entry).unwrap();
                        } else {
                            writeln!(formatted_output_string, "  - {:?}", entry.to_id_entry())
                                .unwrap();
                        }

                        let mut stacktrace = String::new();
                        get_kernel_stracktrace!(metadata; a2l; stacktrace; "      ");

                        if !stacktrace.is_empty() {
                            writeln!(formatted_output_string, "    Kernel Symbols:").unwrap();
                            write!(formatted_output_string, "{}", stacktrace).unwrap();
                        }
                    }
                    _ => bail!("Unexpected bug entry."),
                }
            }
            writeln!(formatted_output_string, "").unwrap();
        }

        if let Some(output_dir) = output_dir {
            let mut ta_bugs_file = File::create(output_dir.join("ta_bugs.yaml"))?;
            ta_bugs_file.write_all(formatted_output_string.as_bytes())?;
        } else {
            print!("{}", formatted_output_string);
        }

        self.timing_end_trace_analysis = Instant::now();
        Ok((self.bugs.len(), ta_entries))
    }

    fn process_trace_entry_write(
        &mut self,
        address: usize,
        size: usize,
        non_temporal: bool,
        id: usize,
        checkpoint_id: isize,
        kernel_stacktrace: Vec<u64>,
    ) {
        macro_rules! check_store {
            ($group:expr; $bug_type:expr) => {
                let mut retained_group = $group.clone();
                retained_group.retain(|&k, _| k >= address && k < address + size);

                for (k, v) in retained_group {
                    if Self::target_store_contains_source_store(k, v.size, address, address + size)
                        || Self::source_store_contains_target_store(
                            k,
                            v.size,
                            address,
                            address + size,
                        )
                    {
                        self.add_bug(
                            $bug_type,
                            Vec::from([v.instruction_id, id]),
                            v.checkpoint_id,
                            v.kernel_stacktrace,
                        );

                        $group.remove(&k);
                    }
                }
            };
        }

        check_store!(self.flushes_pending; BugType::OverwrittenUnflushed);
        check_store!(self.fences_pending; BugType::OverwrittenUnfenced);

        let mut write = Store::new(size, id, checkpoint_id, kernel_stacktrace);

        if non_temporal {
            write.change_state(StoreState::Flushed);
            self.fences_pending.insert(address, write);
        } else {
            self.flushes_pending.insert(address, write);
        }
    }

    fn process_trace_entry_fence(
        &mut self,
        id: usize,
        checkpoint_id: isize,
        kernel_stacktrace: Vec<u64>,
    ) {
        if self.fences_pending.len() == 0 {
            self.add_bug(
                BugType::RedundantFence,
                Vec::from([id]),
                checkpoint_id,
                kernel_stacktrace.clone(),
            );
        }
        self.fences_pending.clear();
        if self.unordered_flushes.len() > 1 {
            self.unordered_flushes.push(id);
            self.add_bug(
                BugType::UnorderedFlushes,
                self.unordered_flushes.clone(),
                checkpoint_id,
                kernel_stacktrace,
            );
        }
        self.unordered_flushes.clear();
    }

    fn process_trace_entry_flush(
        &mut self,
        mnemonic: &String,
        address: usize,
        id: usize,
        checkpoint_id: isize,
        kernel_stacktrace: Vec<u64>,
    ) {
        let mut flushed_stores = 0;
        let flush_end = address + CACHELINE_SIZE;

        let mut retained_group = self.flushes_pending.clone();
        retained_group.retain(|&k, _| k >= address && k < flush_end);
        if retained_group.len() > 0 {
            for (k, mut v) in retained_group {
                if Self::store_is_inside_cacheline(address, CACHELINE_SIZE, k, v.size) {
                    v.change_state(StoreState::Flushed);
                    flushed_stores += 1;
                    self.fences_pending.insert(k, v);
                    self.flushes_pending.remove(&k);
                } else if Self::store_is_partially_inside_cacheline(
                    address,
                    CACHELINE_SIZE,
                    k,
                    v.size,
                ) {
                    if v.state == StoreState::Modified {
                        v.change_state(StoreState::PartiallyFlushed);
                    } else if v.state == StoreState::PartiallyFlushed {
                        self.fences_pending.insert(k, v);
                        self.flushes_pending.remove(&k);
                    }
                    flushed_stores += 1;
                }
            }
        }

        if flushed_stores > 0 {
            match mnemonic.as_ref() {
                "clflushopt" | "clwb" => self.unordered_flushes.push(id),
                _ => (),
            }
        } else {
            self.add_bug(
                BugType::RedundantFlush,
                Vec::from([id]),
                checkpoint_id,
                kernel_stacktrace,
            );
        }
    }

    fn check_remainder(&mut self) {
        for (_, store) in self.flushes_pending.clone() {
            self.add_bug(
                BugType::MissingFlush,
                Vec::from([store.instruction_id]),
                store.checkpoint_id,
                store.kernel_stacktrace,
            );
        }
        for (_, store) in self.fences_pending.clone() {
            self.add_bug(
                BugType::MissingFence,
                Vec::from([store.instruction_id]),
                store.checkpoint_id,
                store.kernel_stacktrace,
            );
        }
        self.fences_pending.clear();
        self.fences_pending.clear();
    }

    // Use the Failure Point tree to deduplicate bugs
    fn add_bug(
        &mut self,
        bug_type: BugType,
        ids: Vec<usize>,
        checkpoint_id: isize,
        kernel_stacktrace: Vec<u64>,
    ) {
        let fpt_bug = FPTBug::new(bug_type.clone(), checkpoint_id);
        let zero_vec = FailurePointTree::get_zero_vec(kernel_stacktrace);
        if self
            .failure_point_tree
            .add_bug(&zero_vec, zero_vec.len(), Some(fpt_bug))
        {
            let mut trace_entries = Vec::new();
            for id in ids {
                trace_entries.push(self.trace_entries.get(&id).unwrap().clone());
            }
            self.bugs
                .push(Bug::new(bug_type, checkpoint_id, trace_entries));
        }
    }

    pub fn get_timing_start_trace_analysis(&self) -> Instant {
        self.timing_start_trace_analysis
    }

    pub fn get_timing_end_trace_analysis(&self) -> Instant {
        self.timing_end_trace_analysis
    }
}
