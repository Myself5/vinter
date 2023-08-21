use crate::CrashImageHash;
use std::ptr::NonNull;

type FPTraceLink = Option<NonNull<FPTraceAddr>>;

#[derive(Debug, Clone)]
pub struct FPTraceAddr {
    addr: usize,
    visited: bool,
    children: Vec<FPTraceLink>,
    parent: FPTraceLink,
    crash_image_hash: Option<CrashImageHash>,
}

impl FPTraceAddr {
    pub fn new(
        addr: usize,
        children: Vec<FPTraceLink>,
        parent: FPTraceLink,
        crash_image_hash: Option<CrashImageHash>,
    ) -> FPTraceAddr {
        FPTraceAddr {
            addr,
            visited: false,
            children,
            parent,
            crash_image_hash,
        }
    }

    pub fn get_addr(&self) -> usize {
        self.addr
    }

    pub fn is_visited(&self) -> bool {
        self.visited
    }
}

pub struct FailurePointTree {
    size: usize,
    leaves: usize,
    root: FPTraceLink,
}

impl FailurePointTree {
    pub fn new() -> FailurePointTree {
        FailurePointTree {
            size: 0,
            leaves: 0,
            root: None,
        }
    }

    // Returns "Path Found" if the full path is contained and Errors on the last link if not
    pub fn contains(&self, addr: &[usize], length: usize) -> Result<bool, FPTraceLink> {
        if unsafe { (*self.root.unwrap().as_ptr()).addr } == addr[0] {
            if length > 1 {
                if let (_, Some(p)) = self.contains_root(self.root, 1, &addr[1..], length - 1) {
                    return Err(Some(p));
                }
            }
            return Ok(true);
        }

        // Tree does not share a common root
        Err(None)
    }

    fn contains_root(
        &self,
        root: FPTraceLink,
        depth: usize,
        addr: &[usize],
        length: usize,
    ) -> (usize, FPTraceLink) {
        for child in unsafe { (*root.unwrap().as_ptr()).children.to_vec() } {
            if unsafe { (*child.unwrap().as_ptr()).addr } == addr[0] {
                if length > 1 {
                    return self.contains_root(child, depth + 1, &addr[1..], length - 1);
                } else {
                    // the call-stack is already fully included
                    return (depth, None);
                }
            }
        }
        // If there's no child with the matching address, return the last common Link
        (depth, root)
    }

    pub fn add(
        &mut self,
        addr: &[usize],
        length: usize,
        crash_image_hash: CrashImageHash,
    ) -> Option<CrashImageHash> {
        if length <= 0 {
            return None;
        }
        if let Some(root) = self.root {
            if unsafe { (*root.as_ptr()).addr } == addr[0] {
                return self.add_to_parent(Some(root), &addr[1..], length - 1, crash_image_hash);
            } else {
                return None;
            } // Otherwise there is no common root -> Something is wrong
        } else {
            // Create our new root
            let new_entry;
            unsafe {
                new_entry = NonNull::new_unchecked(Box::into_raw(Box::new(FPTraceAddr::new(
                    addr[0],
                    Vec::new(),
                    None,
                    None,
                ))));
            } // unsafe
            self.root = Some(new_entry);
            self.size += 1;
            return self.add_to_parent(Some(new_entry), &addr[1..], length - 1, crash_image_hash);
        }
    }

    fn add_to_parent(
        &mut self,
        parent: FPTraceLink,
        addr: &[usize],
        length: usize,
        crash_image_hash: CrashImageHash,
    ) -> Option<CrashImageHash> {
        if length <= 0 {
            return None;
        }

        let next_parent_search = self.contains_root(parent, 1, addr, length);
        let mut crash_image_to_delete = None;

        match next_parent_search {
            (_, None) => (), //No action needed, the path is already contained
            (d, Some(parent)) => {
                let next_parent;
                unsafe {
                    next_parent = Some(NonNull::new_unchecked(Box::into_raw(Box::new(
                        FPTraceAddr::new(addr[d - 1], Vec::new(), Some(parent), None),
                    ))));
                    (*parent.as_ptr()).children.push(next_parent);
                    crash_image_to_delete = (*parent.as_ptr()).crash_image_hash;
                    (*parent.as_ptr()).crash_image_hash = None;
                } // unsafe

                self.size += 1;
                if length - d > 0 {
                    if let Some(hash) =
                        self.add_to_parent(next_parent, &addr[d..], length - d, crash_image_hash)
                    {
                        return Some(hash);
                    }
                } else {
                    self.leaves += 1;
                    unsafe {
                        (*next_parent.unwrap().as_ptr()).crash_image_hash = Some(crash_image_hash);
                    }
                }
            }
        }
        return crash_image_to_delete;
    }

    pub fn print(&self) {
        self.print_root(self.root, 0);

        println!("Total Size: {}", self.size);
        println!("Total Leaves: {}", self.leaves);
    }

    fn print_root(&self, parent: FPTraceLink, level: usize) {
        let visited;
        let has_crash_image;
        let parent_addr;
        let child_vec;
        unsafe {
            visited = if (*parent.unwrap().as_ptr()).visited {
                "v"
            } else {
                "x"
            };
            has_crash_image = if let Some(_) = (*parent.unwrap().as_ptr()).crash_image_hash {
                "i"
            } else {
                "x"
            };
            parent_addr = (*parent.unwrap().as_ptr()).addr;
            child_vec = (*parent.unwrap().as_ptr()).children.to_vec();
        } // unsafe
        for _ in 0..level {
            print!("\t");
        }
        println!("0x{} {} {}", parent_addr, visited, has_crash_image);
        for child in child_vec {
            self.print_root(child, level + 1);
        }
    }

    pub fn search(&self, addr: usize) -> FPTraceLink {
        self.search_root(self.root, addr)
    }

    fn search_root(&self, parent: FPTraceLink, addr: usize) -> FPTraceLink {
        if unsafe {
            !(*parent.unwrap().as_ptr()).visited && (*parent.unwrap().as_ptr()).addr == addr
        } {
            return parent;
        } else {
            for child in unsafe { (*parent.unwrap().as_ptr()).children.to_vec() } {
                if let Some(r) = self.search_root(child, addr) {
                    return Some(r);
                }
            }
        }
        None
    }

    pub fn get_by_addrs(&self, addr: &[usize], length: usize) -> FPTraceLink {
        let ret = self.get_by_addrs_root(self.root, addr, length);
        if let None = ret {
            println!("Addr stack not in tree");
        }
        ret
    }

    fn get_by_addrs_root(&self, parent: FPTraceLink, addr: &[usize], length: usize) -> FPTraceLink {
        if unsafe { (*parent.unwrap().as_ptr()).addr } != addr[0] {
        } else {
            if length > 1 {
                for child in unsafe { (*parent.unwrap().as_ptr()).children.to_vec() } {
                    if let Some(r) = self.get_by_addrs_root(child, &addr[1..], length - 1) {
                        return Some(r);
                    }
                }
            } else {
                return parent;
            }
        }
        None
    }

    pub fn get_path_from_addr(&self, link: FPTraceLink) -> Vec<usize> {
        let mut vec = self.get_path_from_addr_rec(link, Vec::new());
        vec.reverse();
        vec
    }

    fn get_path_from_addr_rec(&self, link: FPTraceLink, mut vec: Vec<usize>) -> Vec<usize> {
        match link {
            Some(l) => unsafe {
                vec.push((*l.as_ptr()).addr);
            },
            None => {
                println!("get_path_from_addr_rec: Invalid link provided");
                return Vec::new();
            }
        }

        if let Some(parent) = unsafe { (*link.unwrap().as_ptr()).parent } {
            self.get_path_from_addr_rec(Some(parent), vec)
        } else {
            vec
        }
    }

    pub fn mark_visited(&self, leaf: FPTraceLink) {
        match leaf {
            Some(l) => unsafe {
                (*l.as_ptr()).visited = true;
                if let Some(p) = (*l.as_ptr()).parent {
                    self.mark_visited(Some(p));
                }
            }, // unsafe
            None => println!("Leaf doesn't exist"),
        }
    }
}
