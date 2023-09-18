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

#[derive(Debug, Clone, Serialize)]
pub struct Bug {
    bug_type: BugType,
    checkpoint: isize,
    id: usize,
}

impl Bug {
    pub fn new(bug_type: BugType, checkpoint: isize, id: usize) -> Bug {
        Bug {
            bug_type,
            checkpoint,
            id,
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
