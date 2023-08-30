use std::ptr::NonNull;
type FPTraceLink = Option<NonNull<FPTraceAddr>>;

#[derive(Debug, Clone)]
pub struct FPTraceAddr {
    addr: u64,
    visited: bool,
    children: Vec<FPTraceLink>,
    parent: FPTraceLink,
}

impl FPTraceAddr {
    pub fn new(addr: u64, children: Vec<FPTraceLink>, parent: FPTraceLink) -> FPTraceAddr {
        FPTraceAddr {
            addr,
            visited: false,
            children,
            parent,
        }
    }

    pub fn get_addr(&self) -> u64 {
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
    // Only used in the example/testing
    pub fn contains(&self, addr: &[u64], length: usize) -> Result<bool, FPTraceLink> {
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
        addr: &[u64],
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

    // Return true if the stack has been added to the tree, false if not or if it has been included before
    pub fn add(&mut self, addr: &[u64], length: usize) -> bool {
        if length <= 0 {
            return false;
        }
        if let Some(root) = self.root {
            if unsafe { (*root.as_ptr()).addr } == addr[0] {
                return self.add_to_parent(Some(root), &addr[1..], length - 1);
            } else {
                return false; // Otherwise there is no common root -> Something is wrong
            }
        } else {
            // Create our new root
            let new_entry;
            unsafe {
                new_entry = NonNull::new_unchecked(Box::into_raw(Box::new(FPTraceAddr::new(
                    addr[0],
                    Vec::new(),
                    None,
                ))));
            } // unsafe
            self.root = Some(new_entry);
            self.size += 1;
            return self.add_to_parent(Some(new_entry), &addr[1..], length - 1);
        }
    }

    // Return true if the stack has been added to the tree, false if not or if it has been included before
    fn add_to_parent(&mut self, parent: FPTraceLink, addr: &[u64], length: usize) -> bool {
        if length <= 0 {
            return false;
        }

        let next_parent_search = self.contains_root(parent, 1, addr, length);

        match next_parent_search {
            (_, None) => return false, //No action needed, the path is already contained
            (d, Some(parent)) => {
                let next_parent;
                unsafe {
                    next_parent = Some(NonNull::new_unchecked(Box::into_raw(Box::new(
                        FPTraceAddr::new(addr[d - 1], Vec::new(), Some(parent)),
                    ))));
                    (*parent.as_ptr()).children.push(next_parent);
                } // unsafe

                self.size += 1;
                if length - d > 0 {
                    return self.add_to_parent(next_parent, &addr[d..], length - d);
                } else {
                    self.leaves += 1;
                    return true;
                }
            }
        }
    }

    // Used in Example/Testing
    pub fn print(&self) {
        self.print_root(self.root, 0);

        println!("Total Size: {}", self.size);
        println!("Total Leaves: {}", self.leaves);
    }

    fn print_root(&self, parent: FPTraceLink, level: usize) {
        let visited;
        let parent_addr;
        let child_vec;
        unsafe {
            visited = if (*parent.unwrap().as_ptr()).visited {
                "v"
            } else {
                "x"
            };
            parent_addr = (*parent.unwrap().as_ptr()).addr;
            child_vec = (*parent.unwrap().as_ptr()).children.to_vec();
        } // unsafe
        for _ in 0..level {
            print!("\t");
        }
        println!("0x{} {}", parent_addr, visited);
        for child in child_vec {
            self.print_root(child, level + 1);
        }
    }

    // Used in Example/Testing
    pub fn search(&self, addr: u64) -> FPTraceLink {
        self.search_root(self.root, addr)
    }

    fn search_root(&self, parent: FPTraceLink, addr: u64) -> FPTraceLink {
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

    // Used in Example/Testing
    pub fn get_by_addrs(&self, addr: &[u64], length: usize) -> FPTraceLink {
        let ret = self.get_by_addrs_root(self.root, addr, length);
        if let None = ret {
            println!("Addr stack not in tree");
        }
        ret
    }

    fn get_by_addrs_root(&self, parent: FPTraceLink, addr: &[u64], length: usize) -> FPTraceLink {
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

    // Used in Example/Testing
    pub fn get_path_from_addr(&self, link: FPTraceLink) -> Vec<u64> {
        let mut vec = self.get_path_from_addr_rec(link, Vec::new());
        vec.reverse();
        vec
    }

    fn get_path_from_addr_rec(&self, link: FPTraceLink, mut vec: Vec<u64>) -> Vec<u64> {
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
