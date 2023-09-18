use serde::Serialize;

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

#[derive(Debug, Clone, PartialEq, Serialize)]
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

#[derive(Debug, Serialize)]
pub struct Bug {
    bug_type: BugType,
    checkpoint: isize,
    trace_ids: Vec<usize>,
}

impl Bug {
    pub fn new(bug_type: BugType, checkpoint: isize, trace_ids: Vec<usize>) -> Bug {
        Bug {
            bug_type,
            checkpoint,
            trace_ids,
        }
    }
}

#[derive(Debug, Clone)]
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
