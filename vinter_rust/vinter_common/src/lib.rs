use serde::Serialize;

pub mod fptree;
pub mod trace;

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

#[derive(Debug, Clone, PartialEq, Serialize)]
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
