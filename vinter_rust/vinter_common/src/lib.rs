use crate::trace::TraceEntry;

pub mod fptree;
pub mod trace;

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

#[derive(Debug, Clone, PartialEq)]
pub enum BugType {
    RedundantFlush,
    RedundantFence,
    MissingFlush,
    MissingFence,
    OverwrittenUnflushed,
    OverwrittenUnfenced,
    // ImplicitFlush, // Unused, but included in the Mumak design
    UnorderedFlushes,
    None,
}

pub struct Bug {
    pub bug_type: BugType,
    pub checkpoint: isize,
    pub trace_entries: Vec<TraceEntry>,
}

impl Bug {
    pub fn new(bug_type: BugType, checkpoint: isize, trace_entries: Vec<TraceEntry>) -> Bug {
        Bug {
            bug_type,
            checkpoint,
            trace_entries,
        }
    }
}

#[derive(Clone)]
pub struct FPTBug {
    bug_type: BugType,
    checkpoint: isize,
}

impl FPTBug {
    pub fn new(bug_type: BugType, checkpoint: isize) -> FPTBug {
        FPTBug {
            bug_type,
            checkpoint,
        }
    }
}
