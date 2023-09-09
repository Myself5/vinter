use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::Command;
use std::rc::Rc;
use std::time::Instant;

use anyhow::{anyhow, bail, Context, Result};
use itertools::Itertools;
use serde::{Serialize, Serializer};

use vinter_common::trace::{self, TraceEntry};

mod image;
mod set;
pub use image::{MemoryImage, MemoryImageMmap, MemoryImageVec};

mod pmem;
pub use pmem::{LineGranularity, X86PersistentMemory};

pub mod config;

mod fptree;
pub use fptree::{FPTraceAddr, FailurePointTree};

const CACHELINE_SIZE: usize = 64;

pub trait Mmss {
    fn mmss(&self) -> String;
}

impl Mmss for std::time::Duration {
    fn mmss(&self) -> String {
        let s = self.as_secs();
        let (m, s) = (s / 60, s % 60);

        format!("{:02}:{:02}", m, s)
    }
}

#[derive(Clone)]
pub struct TraceAnalysisEntry {
    checkpoint_id: isize,
    trace_entry: TraceEntry,
    kernel_stacktrace: Vec<u64>,
}

impl TraceAnalysisEntry {
    fn new(
        checkpoint_id: isize,
        trace_entry: TraceEntry,
        kernel_stacktrace: Vec<u64>,
    ) -> TraceAnalysisEntry {
        TraceAnalysisEntry {
            checkpoint_id,
            trace_entry,
            kernel_stacktrace,
        }
    }
}

#[derive(Clone, PartialEq)]
pub enum BugType {
    RedundantFlush,
    RedundantFence,
    MissingFlush,
    MissingFence,
    OverwrittenUnflushed,
    OverwrittenUnfenced,
    ImplicitFlush,
    UnorderedFlushes,
    None,
}

#[derive(Clone)]
pub struct Bug {
    bug_type: BugType,
    checkpoint: isize,
    id: usize,
    kernel_stacktrace: Vec<u64>,
}

impl Bug {
    pub fn new(
        bug_type: BugType,
        id: usize,
        checkpoint: isize,
        kernel_stacktrace: Vec<u64>,
    ) -> Bug {
        Bug {
            bug_type,
            checkpoint,
            id,
            kernel_stacktrace,
        }
    }
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
    entry: TraceAnalysisEntry,
}

impl Store {
    fn new(size: usize, instruction_id: usize, entry: TraceAnalysisEntry) -> Store {
        Store {
            size,
            instruction_id,
            state: StoreState::Modified,
            entry,
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
    flushes: usize,
    implicit_flushes: usize,
    unordered_flushes: usize,
    timing_start_trace_analysis: Instant,
    timing_end_trace_analysis: Instant,
}

impl TraceAnalyzer {
    pub fn new() -> TraceAnalyzer {
        TraceAnalyzer {
            fences_pending: HashMap::new(),
            flushes_pending: HashMap::new(),
            bugs: Vec::new(),
            flushes: 0,
            implicit_flushes: 0,
            unordered_flushes: 0,
            timing_start_trace_analysis: Instant::now(),
            timing_end_trace_analysis: Instant::now(),
        }
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

    pub fn analyze_trace(&mut self, trace_entry_vec: Vec<TraceAnalysisEntry>) -> usize {
        self.timing_start_trace_analysis = Instant::now();
        for entry in trace_entry_vec {
            match entry.clone().trace_entry {
                TraceEntry::Write {
                    id,
                    address,
                    size,
                    non_temporal,
                    ..
                } => self.process_trace_entry_write(address, size, non_temporal, id, entry),
                TraceEntry::Fence { id, .. } => self.process_trace_entry_fence(id, entry),
                TraceEntry::Flush {
                    id,
                    mnemonic,
                    address,
                    ..
                } => self.process_trace_entry_flush(&mnemonic, address, id, entry),
                _ => (),
            }
        }

        self.check_remainder();

        self.timing_end_trace_analysis = Instant::now();
        self.bugs.len()
    }

    fn process_trace_entry_write(
        &mut self,
        address: usize,
        size: usize,
        non_temporal: bool,
        id: usize,
        entry: TraceAnalysisEntry,
    ) {
        let mut write = Store::new(size, id, entry);
        self.check_store_flush(address, size);
        self.check_store_fence(address, size);
        if non_temporal {
            write.change_state(StoreState::Flushed);
            self.fences_pending.insert(address, write);
        } else {
            self.flushes_pending.insert(address, write);
        }
    }

    fn check_store_fence(&mut self, address: usize, size: usize) {
        let write_end = address + size;

        let mut retained_group = self.fences_pending.clone();
        retained_group.retain(|&k, _| k >= address && k < write_end);

        for (k, v) in retained_group {
            if Self::target_store_contains_source_store(k, v.size, address, write_end)
                || Self::source_store_contains_target_store(k, v.size, address, write_end)
            {
                self.add_bug(BugType::OverwrittenUnfenced, v.instruction_id, v.entry);

                self.fences_pending.remove(&k);
            }
        }
    }

    fn check_store_flush(&mut self, address: usize, size: usize) {
        let write_end = address + size;

        let mut retained_group = self.flushes_pending.clone();
        retained_group.retain(|&k, _| k >= address && k < write_end);

        for (k, v) in retained_group {
            if Self::target_store_contains_source_store(k, v.size, address, write_end)
                || Self::source_store_contains_target_store(k, v.size, address, write_end)
            {
                self.add_bug(BugType::OverwrittenUnflushed, v.instruction_id, v.entry);

                self.flushes_pending.remove(&k);
            }
        }
    }

    fn process_trace_entry_fence(&mut self, id: usize, entry: TraceAnalysisEntry) {
        if self.fences_pending.len() == 0 {
            self.add_bug(BugType::RedundantFence, id, entry.clone());
        }
        self.fences_pending.clear();
        if self.unordered_flushes > 1 {
            self.add_bug(BugType::UnorderedFlushes, id, entry);
        }
        self.unordered_flushes = 0;
    }

    fn process_trace_entry_flush(
        &mut self,
        mnemonic: &String,
        address: usize,
        id: usize,
        entry: TraceAnalysisEntry,
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

        self.flushes += 1;
        self.implicit_flushes += flushed_stores;

        if flushed_stores > 0 {
            match mnemonic.as_ref() {
                "clflushopt" | "clwb" => self.unordered_flushes += 1,
                _ => (),
            }
        } else {
            self.add_bug(BugType::RedundantFlush, id, entry);
        }
    }

    fn check_remainder(&mut self) {
        for (_, store) in self.flushes_pending.clone() {
            self.add_bug(BugType::MissingFlush, store.instruction_id, store.entry);
        }
        for (_, store) in self.fences_pending.clone() {
            self.add_bug(BugType::MissingFence, store.instruction_id, store.entry);
        }
        self.fences_pending.clear();
        self.fences_pending.clear();
    }

    pub fn get_bugs(&self) -> Vec<Bug> {
        self.bugs.clone()
    }

    // Use the Failure Point tree to deduplicate bugs
    fn add_bug(&mut self, bug_type: BugType, id: usize, entry: TraceAnalysisEntry) {
        let bug = Bug::new(bug_type, id, entry.checkpoint_id, entry.kernel_stacktrace);

        let mut is_contained = false;

        // Check if the same bug type and and stacktrace is already contained for this checkpoint
        for contained_bug in self.bugs.clone() {
            if contained_bug.bug_type == bug.bug_type
                && contained_bug.checkpoint == bug.checkpoint
                && contained_bug.kernel_stacktrace == bug.kernel_stacktrace
            {
                is_contained = true;
                break;
            }
        }

        if !is_contained {
            self.bugs.push(bug);
        }
    }

    pub fn get_timing_start_trace_analysis(&self) -> Instant {
        self.timing_start_trace_analysis
    }

    pub fn get_timing_end_trace_analysis(&self) -> Instant {
        self.timing_end_trace_analysis
    }

}

pub struct MemoryReplayer {
    pub mem: Rc<RefCell<X86PersistentMemory>>,
}

impl MemoryReplayer {
    pub fn new(mem: X86PersistentMemory) -> MemoryReplayer {
        MemoryReplayer {
            mem: Rc::new(RefCell::new(mem)),
        }
    }

    pub fn process_trace<'a>(
        &'a mut self,
        file: impl BufRead + 'a,
    ) -> impl Iterator<Item = Result<trace::TraceEntry>> + 'a {
        let mut deferred_fence = false;
        trace::parse_trace_file_bin(file).map(move |entry| {
            if deferred_fence {
                self.mem.borrow_mut().fence();
                deferred_fence = false;
            }
            match &entry {
                Ok(TraceEntry::Write {
                    id: _,
                    address,
                    size: _,
                    content,
                    non_temporal,
                    metadata,
                }) => {
                    self.mem
                        .borrow_mut()
                        .write(*address, content, *non_temporal, metadata);
                }
                Ok(TraceEntry::Fence { .. }) => {
                    // A fence persists all flushed cachelines. For crash image
                    // generation, we still need to see these flushed lines, so
                    // defer the flush until the next iteration.
                    deferred_fence = true;
                }
                Ok(TraceEntry::Flush {
                    id: _,
                    mnemonic,
                    address,
                    ..
                }) => {
                    let mut mem = self.mem.borrow_mut();
                    match mnemonic.as_ref() {
                        "clwb" => {
                            mem.clwb(*address, None);
                        }
                        "clflush" => {
                            mem.clwb(*address, None);
                            // Note that this fence is not completely correct (in that we may lose
                            // bugs), as clflushes are only ordered among themselves (and some other
                            // things), but *not* among CLFLUSHOPT and CLWB.  However applications
                            // usually don't mix those anyway.
                            mem.fence();
                        }
                        m => {
                            bail!("unknown flush mnemonic {}", m);
                        }
                    }
                }
                _ => {}
            };
            entry
        })
    }
}

pub enum CrashImageGenerator {
    None,
    Heuristic,
    FailurePointTree,
}

impl std::fmt::Display for CrashImageGenerator {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            CrashImageGenerator::None => write!(f, "None"),
            CrashImageGenerator::Heuristic => write!(f, "Heuristic"),
            CrashImageGenerator::FailurePointTree => write!(f, "FailurePointTree"),
        }
    }
}

#[derive(Debug, Serialize)]
pub enum CrashPersistenceType {
    /// We always create an image at a checkpoint, even if there are no writes.
    NoWrites,
    /// Image with no pending writes persisted.
    NothingPersisted,
    /// Image with all pending writes persisted.
    FullyPersisted { dirty_lines: Vec<usize> },
    /// Image with a subset of all writes persisted.
    StrictSubsetPersisted {
        strict_subset_lines: Vec<usize>,
        partial_write_indices: Vec<usize>,
        dirty_lines: Vec<usize>,
    },
}

#[derive(Debug, Serialize)]
pub struct CrashMetadata {
    pub fence_id: usize,
    /// -1 is before the first checkpoint
    pub checkpoint_id: isize,
    pub persistence_type: CrashPersistenceType,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct SemanticStateHash(blake3::Hash);
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct CrashImageHash(blake3::Hash);

macro_rules! impl_serialize_hash {
    ($t: ty) => {
        impl Serialize for $t {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0.to_hex())
            }
        }
    };
}
impl_serialize_hash!(SemanticStateHash);
impl_serialize_hash!(CrashImageHash);

#[derive(Debug, Serialize)]
pub struct SemanticState {
    pub hash: SemanticStateHash,
    pub successful: bool,
    pub originating_images: Vec<CrashImageHash>,
}

/// Did we use a crash image for a heuristic?
#[derive(Debug, Serialize)]
pub enum HeuristicState {
    /// No, the crash image was not considered (only fully-persisted crash images are used for the heuristic).
    NotConsidered,
    /// Yes, we applied the heuristic and traced the post-recovery code.
    HeuristicApplied {
        heuristic_images: Vec<CrashImageHash>,
        modified_lines: usize,
        read_lines: usize,
    },
    /// Heuristic was disabled, we used a subset of all modified lines.
    AllConsidered { modified_lines: usize },
}

/// Describes a crash image and all CrashMetadata that have been discovered to lead to this crash image.
#[derive(Debug, Serialize)]
pub struct CrashImage {
    pub hash: CrashImageHash,
    pub heuristic: HeuristicState,
    pub originating_crashes: Vec<CrashMetadata>,
}

impl CrashImage {
    pub fn new(hash: CrashImageHash) -> CrashImage {
        CrashImage {
            hash,
            heuristic: HeuristicState::NotConsidered,
            originating_crashes: Vec::new(),
        }
    }
}

/// Tries to find a file with the given name adjacent to our executable.
fn adjacent_file(name: &OsStr) -> Option<PathBuf> {
    let current_exe = std::env::current_exe().ok()?;
    let dir = current_exe.parent()?;
    let file = dir.join(name);
    if file.exists() {
        Some(file)
    } else {
        None
    }
}

fn trace_command() -> Result<Command> {
    Ok(Command::new(match std::env::var_os("VINTER_TRACE_CMD") {
        Some(path) => PathBuf::from(path),
        None => {
            if let Some(path) = adjacent_file(OsStr::new("vinter_trace.py")) {
                path
            } else {
                bail!("VINTER_TRACE_CMD is not set");
            }
        }
    }))
}

/// Concatenates two OsStr.
fn concat_osstr<A: Into<OsString>, B: AsRef<OsStr> + ?Sized>(a: A, b: &B) -> OsString {
    let mut str = a.into();
    str.push(b);
    return str;
}

// TODO: Make these command-line parameters.

/// How many random subsets of all unflushed lines to consider when generating crash images.
const MAX_UNPERSISTED_SUBSETS: usize = 20;
/// log2(MAX_UNPERSISTED_SUBSETS)
const MAX_UNPERSISTED_SUBSETS_LOG2: usize = 4;
/// For each random subset, how many (in-order) partial flushes to consider in case of multiple
/// writes to the same line. Note that the maximum number of generated crash images at one fence is
/// thus `MAX_UNPERSISTED_SUBSETS * MAX_PARTIAL_FLUSHES_COUNT`.
const MAX_PARTIAL_FLUSHES_COUNT: usize = 20;

pub struct GenericCrashImageGenerator {
    vm_config_path: PathBuf,
    vm_config: config::Config,
    test_config: config::Test,
    output_dir: PathBuf,
    generator_config: CrashImageGenerator,
    failure_point_tree: FailurePointTree,
    log: File,
    rng: fastrand::Rng,
    /// Generated crash images, indexed by their hash.
    pub crash_images: HashMap<CrashImageHash, CrashImage>,
    /// Semantic states extracted the crash images, indexed by their hash.
    pub semantic_states: HashMap<SemanticStateHash, SemanticState>,
    fail_recovery_silent: bool,
    failed_recovery_count: usize,
    trace_analysis: bool,
    timing_start_trace: Instant,
    timing_start_crash_image_generation: Instant,
    timing_start_semantic_state_generation: Instant,
    timing_end_semantic_state_generation: Instant,
}

impl GenericCrashImageGenerator {
    pub fn new(
        vm_config_path: PathBuf,
        test_config_path: PathBuf,
        mut output_dir: PathBuf,
        generator_config: CrashImageGenerator,
        fail_recovery_silent: bool,
        trace_analysis: bool,
    ) -> Result<Self> {
        let vm_config: config::Config = {
            let f = File::open(&vm_config_path).context("could not open VM config file")?;
            serde_yaml::from_reader(f).context("could not parse VM config file")?
        };
        let test_config = {
            let f = File::open(&test_config_path).context("could not open test config file")?;
            serde_yaml::from_reader(f).context("could not parse test config file")?
        };
        // Build full output path: <output_dir>/vm_foo/test_bar/
        let vm_name = vm_config_path
            .file_stem()
            .ok_or_else(|| anyhow!("invalid VM config file name"))?;
        output_dir.push(vm_name);
        let test_name = test_config_path
            .file_stem()
            .ok_or_else(|| anyhow!("invalid test config file name"))?;
        output_dir.push(test_name);
        if output_dir.exists() {
            bail!("output directory {} already exists", output_dir.display());
        }
        std::fs::create_dir_all(&output_dir).context("could not create output directory")?;
        std::fs::copy(
            &vm_config_path,
            output_dir.join(concat_osstr(vm_name, ".yaml")),
        )
        .context("could not copy VM config file")?;
        std::fs::copy(
            &test_config_path,
            output_dir.join(concat_osstr(test_name, ".yaml")),
        )
        .context("could not copy test config file")?;
        std::fs::create_dir(output_dir.join("crash_images"))
            .context("could not create crash_images directory")?;
        std::fs::create_dir(output_dir.join("crash_image_states"))
            .context("could not create crash_image_states directory")?;
        std::fs::create_dir(output_dir.join("recovery_traces"))
            .context("could not create recovery_traces directory")?;
        std::fs::create_dir(output_dir.join("semantic_states"))
            .context("could not create semantic_states directory")?;
        let log = File::create(output_dir.join("trace2img.log"))
            .context("could not create trace2img.log")?;
        // create a base image for snapshots
        let status = Command::new("qemu-img")
            .args(["create", "-f", "qcow2"])
            .arg(output_dir.join("img.qcow2").as_os_str())
            .arg("1G")
            .stdout(log.try_clone()?)
            .status()?;
        if !status.success() {
            bail!("qemu-img failed with status {}", status);
        }

        Ok(GenericCrashImageGenerator {
            vm_config_path,
            vm_config,
            test_config,
            output_dir,
            generator_config,
            failure_point_tree: FailurePointTree::new(),
            log,
            rng: fastrand::Rng::with_seed(1633634632),
            crash_images: HashMap::new(),
            semantic_states: HashMap::new(),
            fail_recovery_silent,
            failed_recovery_count: 0,
            trace_analysis,
            timing_start_trace: Instant::now(),
            timing_start_crash_image_generation: Instant::now(),
            timing_start_semantic_state_generation: Instant::now(),
            timing_end_semantic_state_generation: Instant::now(),
        })
    }

    /// Start a VM and trace test execution.
    pub fn trace_pre_failure(&mut self) -> Result<()> {
        self.timing_start_trace = Instant::now();

        let cmd = format!("cat /proc/uptime; cat /proc/uptime; cat /proc/uptime; {prefix} && {suffix} && hypercall success; cat /proc/uptime",
            prefix = self.vm_config.commands.get("trace_cmd_prefix").ok_or_else(|| anyhow!("missing trace_cmd_prefix in VM configuration"))?,
            suffix = self.test_config.trace_cmd_suffix);
        let metadata_arg = if self.trace_analysis
            || matches!(self.generator_config, CrashImageGenerator::FailurePointTree)
        {
            Vec::from(["--metadata", "kernel_stacktrace"])
        } else {
            Vec::new()
        };
        let status = trace_command()?
            .arg("--qcow")
            .arg(self.output_dir.join("img.qcow2"))
            .arg("--trace")
            .arg(self.trace_path())
            .args(["--trace-what", "write,fence,flush,hypercall"])
            .arg("--run")
            .arg(cmd)
            .arg("--save-pmem")
            .arg(self.output_dir.join("final.img"))
            .arg(&self.vm_config_path)
            .args(metadata_arg)
            .stderr(self.log.try_clone()?)
            .stdout(self.log.try_clone()?)
            .status()?;
        if !status.success() {
            bail!("pre-failure tracing failed with status {}", status);
        }
        Ok(())
    }

    /// Trace recovery of a crash image, for use in the cross-failure heuristic.
    pub fn trace_recovery(&self, crash_img_hash: &CrashImageHash) -> Result<PathBuf> {
        let cmd = self
            .vm_config
            .commands
            .get("recovery_cmd")
            .ok_or_else(|| anyhow!("missing recovery_cmd in VM configuration"))?;
        let path = self.recovery_trace_path(crash_img_hash);
        let status = trace_command()?
            .arg("--qcow")
            .arg(self.output_dir.join("img.qcow2"))
            .args(["--load-snapshot", "boot"])
            .arg("--load-pmem")
            .arg(self.crash_image_path(crash_img_hash))
            .arg("--trace")
            .arg(&path)
            .args(["--trace-what", "read,hypercall"])
            .arg("--run")
            .arg(cmd)
            .arg(&self.vm_config_path)
            .stdout(self.log.try_clone()?)
            .stderr(self.log.try_clone()?)
            .status()?;
        if !status.success() {
            bail!("pre-failure tracing failed with status {}", status);
        }
        Ok(path)
    }

    /// Returns the path to the pre-failure trace file.
    fn trace_path(&self) -> PathBuf {
        self.output_dir.join("trace.bin")
    }

    /// Returns the output path to a crash image with the given hash.
    fn crash_image_path(&self, hash: &CrashImageHash) -> PathBuf {
        self.output_dir
            .join("crash_images")
            .join(format!("{}.img", hash.0.to_hex()))
    }

    /// Returns the output path to a post-failure recovery trace.
    fn recovery_trace_path(&self, hash: &CrashImageHash) -> PathBuf {
        self.output_dir
            .join("recovery_traces")
            .join(format!("{}.bin", hash.0.to_hex()))
    }

    /// Returns the output path to a semantic state for the given crash image.
    fn crash_image_state_path(&self, hash: &CrashImageHash, ext: &str) -> PathBuf {
        // TODO: enum instead of str for ext?
        self.output_dir
            .join("crash_image_states")
            .join(format!("{}.{}", hash.0.to_hex(), ext))
    }

    /// Returns the output path to a semantic state, indexed by its own hash.
    fn semantic_state_path(&self, hash: &SemanticStateHash) -> PathBuf {
        self.output_dir
            .join("semantic_states")
            .join(format!("{}.txt", hash.0.to_hex()))
    }

    fn run_state_extractor(&self, crash_img: &CrashImage) -> Result<SemanticState> {
        let cmd = format!(
            "{prefix} && {suffix} && hypercall success",
            prefix = self
                .vm_config
                .commands
                .get("dump_cmd_prefix")
                .ok_or_else(|| anyhow!("missing dump_cmd_prefix in VM configuration"))?,
            suffix = self.test_config.dump_cmd_suffix
        );
        let cmd_output_path = self.crash_image_state_path(&crash_img.hash, "state.txt");
        let trace_path = self.crash_image_state_path(&crash_img.hash, "trace.bin");
        let status = trace_command()?
            .arg("--qcow")
            .arg(self.output_dir.join("img.qcow2"))
            .args(["--load-snapshot", "boot"])
            .arg("--load-pmem")
            .arg(self.crash_image_path(&crash_img.hash))
            .arg("--trace")
            .arg(&trace_path)
            .args(["--trace-what", "hypercall"])
            .arg("--run")
            .arg(cmd)
            .arg("--cmd-output")
            .arg(&cmd_output_path)
            .arg(&self.vm_config_path)
            .stdout(self.log.try_clone()?)
            .stderr(self.log.try_clone()?)
            .status()?;
        if !status.success() {
            bail!("semantic state extraction failed with status {}", status);
        }
        let mut hasher = blake3::Hasher::new();
        std::io::copy(&mut File::open(&cmd_output_path)?, &mut hasher)
            .context("could not read semantic state output file")?;
        let mut successful = false;
        for entry in trace::parse_trace_file_bin(BufReader::new(
            File::open(&trace_path).context("could not open trace output file")?,
        )) {
            match entry? {
                TraceEntry::Hypercall { action, .. } if action == "success" => {
                    successful = true;
                }
                _ => {}
            }
        }
        Ok(SemanticState {
            hash: SemanticStateHash(hasher.finalize()),
            successful,
            // note: creating an empty Vec does not allocate
            originating_images: Vec::new(),
        })
    }

    fn insert_crash_image(
        &mut self,
        fence_id: usize,
        mem: &X86PersistentMemory,
        checkpoint_id: isize,
        callstack_option: Option<&[u64]>,
    ) -> Result<()> {
        use std::collections::hash_map::Entry;
        macro_rules! image_entry {
            ($mem:expr) => {{
                let hash = CrashImageHash($mem.blake3());
                let path = self.crash_image_path(&hash);
                match self.crash_images.entry(hash) {
                    Entry::Vacant(e) => {
                        $mem.image.persist(&mut File::create(path)?)?;
                        e.insert(CrashImage::new(hash.clone()))
                    }
                    // the closure will never be called, it just makes the borrow checker happy
                    e => e.or_insert_with(|| CrashImage::new(hash.clone())),
                }
            }};
        }

        if let CrashImageGenerator::FailurePointTree = self.generator_config {
            match callstack_option {
                Some(callstack) => {
                    // give the stack a common root (0)
                    let mut vec = Vec::from([0]);
                    vec.extend_from_slice(callstack);
                    if !self.failure_point_tree.add(&vec, vec.len()) {
                        // This specific callstack is already included, skip
                        return Ok(());
                    }
                }
                _ => (), // "Hypercalls" provide a "None" callstack, always insert them
            }
        }

        let no_writes = mem.unpersisted_content.is_empty();

        // At each relevant fence, create crash images:
        // 1. with no pending writes persisted
        image_entry!(mem).originating_crashes.push(CrashMetadata {
            fence_id,
            persistence_type: if no_writes {
                CrashPersistenceType::NoWrites
            } else {
                CrashPersistenceType::NothingPersisted
            },
            checkpoint_id,
        });

        // At a checkpoint, we create images even if there are no pending writes.
        // Skip computing the other images and running the heuristic in this case.
        if no_writes {
            return Ok(());
        }

        // 2. with all pending writes persisted
        let mut fully_persisted_mem = mem.try_clone()?;
        fully_persisted_mem.persist_unpersisted();
        let fully_persisted_img = image_entry!(&fully_persisted_mem);
        fully_persisted_img.originating_crashes.push(CrashMetadata {
            fence_id,
            persistence_type: CrashPersistenceType::FullyPersisted {
                dirty_lines: mem.unpersisted_content.keys().copied().collect(),
            },
            checkpoint_id,
        });
        let fully_persisted_img_hash = fully_persisted_img.hash;

        match self.generator_config {
            CrashImageGenerator::Heuristic | CrashImageGenerator::None => {
                // 3. with subsets chosen randomly or by heuristic
                if let HeuristicState::NotConsidered = fully_persisted_img.heuristic {
                    let line_granularity: usize = mem.line_granularity().into();

                    let unpersisted_reads_lines: Vec<usize> =
                        if let CrashImageGenerator::Heuristic = self.generator_config {
                            let hash = fully_persisted_img.hash;
                            let mut success = false;
                            // trace2img.py tracks these only for statistic purposes
                            // let mut unpersisted_reads: HashSet<(usize, usize)> = HashSet::new();
                            let mut unpersisted_reads_lines: HashSet<usize> = HashSet::new();
                            let trace_path = self
                                .trace_recovery(&hash)
                                .context("recovery trace failed")?;
                            let trace_file = File::open(trace_path)
                                .context("could not open recovery trace file")?;
                            for entry in trace::parse_trace_file_bin(BufReader::new(trace_file)) {
                                match entry? {
                                    TraceEntry::Hypercall { action, .. } if action == "success" => {
                                        success = true;
                                    }
                                    TraceEntry::Read { address, size, .. } => {
                                        let min_line_number = address / line_granularity;
                                        let max_line_number =
                                            (address + size - 1) / line_granularity;
                                        for line_number in min_line_number..=max_line_number {
                                            if let Some(line) =
                                                mem.unpersisted_content.get(&line_number)
                                            {
                                                if line.overlaps_access(address, size) {
                                                    // unpersisted_reads.insert((address, size));
                                                    unpersisted_reads_lines.insert(line_number);
                                                }
                                            }
                                        }
                                    }
                                    _ => {}
                                }
                            }
                            if !success {
                                if !self.fail_recovery_silent {
                                    // Ignore errors here, state extraction will most likely also fail later on.
                                    println!("Recovery for crash image {:?} failed", hash);
                                }
                                self.failed_recovery_count += 1;
                            }
                            // unwrap: will never panic since we inserted the image above.
                            self.crash_images
                                .get_mut(&fully_persisted_img_hash)
                                .unwrap()
                                .heuristic = HeuristicState::HeuristicApplied {
                                heuristic_images: Vec::new(),
                                modified_lines: mem.unpersisted_content.len(),
                                read_lines: unpersisted_reads_lines.len(),
                            };

                            unpersisted_reads_lines.drain().collect()
                        } else {
                            // Without heuristic, consider all modified lines.
                            fully_persisted_img.heuristic = HeuristicState::AllConsidered {
                                modified_lines: mem.unpersisted_content.len(),
                            };
                            mem.unpersisted_content.keys().copied().collect()
                        };
                    // Do we have any unpersisted reads?
                    if !unpersisted_reads_lines.is_empty() {
                        let mut heuristic_images = Vec::new();
                        let random_subsets: Vec<Vec<usize>> =
                            if unpersisted_reads_lines.len() <= MAX_UNPERSISTED_SUBSETS_LOG2 {
                                // Skip the empty set in the powerset.
                                unpersisted_reads_lines
                                    .iter()
                                    .copied()
                                    .powerset()
                                    .skip(1)
                                    .collect()
                            } else {
                                set::random_subsets(&mut self.rng, &unpersisted_reads_lines)
                                    .filter(|vec| !vec.is_empty())
                                    .take(MAX_UNPERSISTED_SUBSETS)
                                    .collect()
                            };
                        for random_lines in random_subsets {
                            let partial_flushes_count = random_lines
                                .iter()
                                .map(|line_number| {
                                    mem.unpersisted_content[line_number].all_writes().len()
                                })
                                .fold(0, |acc, x| acc * x);
                            let line_partial_writes: Vec<Vec<usize>> = random_lines
                                .iter()
                                .map(|line_number| {
                                    let writes_count =
                                        mem.unpersisted_content[line_number].all_writes().len();
                                    if partial_flushes_count > MAX_PARTIAL_FLUSHES_COUNT {
                                        if writes_count <= 1 {
                                            vec![writes_count]
                                        } else {
                                            vec![writes_count, self.rng.usize(1..writes_count)]
                                        }
                                    } else {
                                        (1..=writes_count).collect()
                                    }
                                })
                                .collect();
                            for partial_write_indices in
                                line_partial_writes.iter().multi_cartesian_product()
                            {
                                let mut subset_persisted_mem = mem.try_clone()?;
                                for (line_number, flush_writes_limit) in random_lines
                                    .iter()
                                    .copied()
                                    .zip(partial_write_indices.iter().copied())
                                {
                                    subset_persisted_mem.clwb(
                                        line_number * line_granularity,
                                        Some(*flush_writes_limit),
                                    );
                                    subset_persisted_mem.fence_line(line_number);
                                }
                                let entry = image_entry!(&subset_persisted_mem);
                                entry.originating_crashes.push(CrashMetadata {
                                    fence_id,
                                    persistence_type: CrashPersistenceType::StrictSubsetPersisted {
                                        strict_subset_lines: random_lines.clone(),
                                        partial_write_indices: partial_write_indices
                                            .iter()
                                            .map(|&x| *x)
                                            .collect(),
                                        // Dirty lines are all lines that are not (fully) persisted in this image.
                                        // First, all lines that are not in random_lines at all.
                                        dirty_lines: mem
                                            .unpersisted_content
                                            .keys()
                                            .copied()
                                            .collect::<HashSet<_>>()
                                            .difference(&random_lines.iter().copied().collect())
                                            .copied()
                                            .collect::<HashSet<_>>()
                                            // Then, all lines that are partially included (i.e., not with all writes).
                                            .union(
                                                &random_lines
                                                    .iter()
                                                    .zip(partial_write_indices.iter().copied())
                                                    .filter_map(|(line, &writes_limit)| {
                                                        if mem.unpersisted_content[line]
                                                            .all_writes()
                                                            .len()
                                                            > writes_limit
                                                        {
                                                            Some(*line)
                                                        } else {
                                                            None
                                                        }
                                                    })
                                                    .collect(),
                                            )
                                            .copied()
                                            .collect(),
                                    },
                                    checkpoint_id,
                                });
                                heuristic_images.push(entry.hash);
                            }
                        }
                        if let HeuristicState::HeuristicApplied {
                            heuristic_images: imgs,
                            ..
                        } = &mut self
                            .crash_images
                            .get_mut(&fully_persisted_img_hash)
                            .unwrap()
                            .heuristic
                        {
                            std::mem::swap(&mut heuristic_images, imgs);
                        }
                    }
                }
            }
            // Failure Point Tree handling has been done before, so there's nothing to do here
            _ => (),
        }
        Ok(())
    }

    /// Replay the generated trace and generate crash images.
    pub fn replay(&mut self) -> Result<(usize, Vec<TraceAnalysisEntry>)> {
        use std::collections::hash_map::Entry;

        let mut current_writes = false;
        let mut fences_or_flushes_with_writes: usize = 0;
        let mut last_hypercall_checkpoint: isize = -1;
        let mut pre_failure_success = false;
        let mut checkpoint_ids: HashMap<isize, usize> = HashMap::new();
        let mut trace_entry_vec = Vec::new();

        let checkpoint_range = self
            .test_config
            .checkpoint_range
            .map(|(start, end)| start..end);
        let within_checkpoint_range = |checkpoint_id| {
            checkpoint_range.is_none()
                || checkpoint_range.as_ref().unwrap().contains(&checkpoint_id)
        };

        // unwrap: PMEM size will always fit in u64/usize
        let image = MemoryImageMmap::new_in(
            &self.output_dir,
            self.vm_config.vm.pmem_len.try_into().unwrap(),
        )?;
        let mem = X86PersistentMemory::new(image, LineGranularity::Word)?;
        let mut replayer = MemoryReplayer::new(mem);

        // grab a reference to the memory so that we can access it while processing the trace
        let replayer_mem = replayer.mem.clone();
        let trace_file = File::open(self.trace_path()).context("could not open trace file")?;

        let processed_trace = replayer.process_trace(BufReader::new(trace_file));

        self.timing_start_crash_image_generation = Instant::now();

        for entry in processed_trace {
            let trace_entry = entry?;
            match trace_entry.clone() {
                TraceEntry::Flush { id, metadata, .. } => {
                    if self.trace_analysis && within_checkpoint_range(last_hypercall_checkpoint) {
                        trace_entry_vec.push(TraceAnalysisEntry::new(
                            last_hypercall_checkpoint,
                            trace_entry,
                            metadata.kernel_stacktrace.clone(),
                        ));
                    }
                    if current_writes && within_checkpoint_range(last_hypercall_checkpoint) {
                        // Only insert crash images for flushes when using the FPT
                        if let CrashImageGenerator::FailurePointTree = self.generator_config {
                            self.insert_crash_image(
                                id,
                                &replayer_mem.borrow(),
                                last_hypercall_checkpoint,
                                Some(&metadata.kernel_stacktrace),
                            )?;
                            current_writes = false;
                            fences_or_flushes_with_writes += 1;
                        }
                    }
                }
                TraceEntry::Fence { id, metadata, .. } => {
                    if self.trace_analysis && within_checkpoint_range(last_hypercall_checkpoint) {
                        trace_entry_vec.push(TraceAnalysisEntry::new(
                            last_hypercall_checkpoint,
                            trace_entry,
                            metadata.kernel_stacktrace.clone(),
                        ));
                    }
                    if current_writes && within_checkpoint_range(last_hypercall_checkpoint) {
                        self.insert_crash_image(
                            id,
                            &replayer_mem.borrow(),
                            last_hypercall_checkpoint,
                            Some(&metadata.kernel_stacktrace),
                        )?;
                        current_writes = false;
                        fences_or_flushes_with_writes += 1;
                    }
                }
                TraceEntry::Write { metadata, .. } => {
                    if self.trace_analysis && within_checkpoint_range(last_hypercall_checkpoint) {
                        trace_entry_vec.push(TraceAnalysisEntry::new(
                            last_hypercall_checkpoint,
                            trace_entry,
                            metadata.kernel_stacktrace.clone(),
                        ));
                    }
                    current_writes = true;
                }
                TraceEntry::Hypercall {
                    id, action, value, ..
                } => match action.as_ref() {
                    "checkpoint" => {
                        last_hypercall_checkpoint =
                            value.parse().context("invalid checkpoint value")?;
                        match checkpoint_ids.entry(last_hypercall_checkpoint) {
                            Entry::Vacant(e) => {
                                e.insert(id);
                            }
                            _ => {
                                bail!("duplicate checkpoint id {}", last_hypercall_checkpoint);
                            }
                        }
                        // Create a single crash image after the checkpoint range to allow checking for SFS.
                        if within_checkpoint_range(last_hypercall_checkpoint)
                            || self.test_config.checkpoint_range.map(|(_start, end)| end)
                                == Some(last_hypercall_checkpoint)
                        {
                            self.insert_crash_image(
                                id,
                                &replayer_mem.borrow(),
                                last_hypercall_checkpoint,
                                None,
                            )?;
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
                _ => {}
            }
        }

        let index_file = File::create(self.output_dir.join("crash_images").join("index.yaml"))?;
        serde_yaml::to_writer(&index_file, &self.crash_images)
            .context("failed writing crash_images/index.yaml")?;

        Ok((fences_or_flushes_with_writes, trace_entry_vec))
    }

    /// Extract the semantic state of each crash image.
    pub fn extract_semantic_states(&mut self) -> Result<()> {
        self.timing_start_semantic_state_generation = Instant::now();

        let mut states = HashMap::new();
        for (image_hash, image) in &self.crash_images {
            let state = self.run_state_extractor(image)?;
            states
                .entry(state.hash)
                .or_insert(state)
                .originating_images
                .push(*image_hash);
        }

        // copy unique semantic states
        for (state_hash, state) in &states {
            std::fs::copy(
                self.crash_image_state_path(&state.originating_images[0], "state.txt"),
                self.semantic_state_path(state_hash),
            )?;
        }
        let index_file = File::create(self.output_dir.join("semantic_states").join("index.yaml"))?;
        serde_yaml::to_writer(&index_file, &states)
            .context("failed writing semantic_states/index.yaml")?;

        self.semantic_states = states;
        self.timing_end_semantic_state_generation = Instant::now();
        Ok(())
    }

    pub fn get_failed_recovery_count(&self) -> usize {
        self.failed_recovery_count
    }

    pub fn get_timing_trace(&self) -> Instant {
        self.timing_start_trace
    }

    pub fn get_timing_start_crash_image_generation(&self) -> Instant {
        self.timing_start_crash_image_generation
    }

    pub fn get_timing_start_semantic_state_generation(&self) -> Instant {
        self.timing_start_semantic_state_generation
    }

    pub fn get_timing_end_semantic_state_generation(&self) -> Instant {
        self.timing_end_semantic_state_generation
    }
}
