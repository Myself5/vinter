use vinter_trace2img::{CrashImageHash, FPTraceAddr, FailurePointTree};

fn main() {
    let mut tree = FailurePointTree::new();
    println!("Creating Tree:\n");
    let hash = CrashImageHash::new(blake3::hash(b"testhash"));
    let other_hash = CrashImageHash::new(blake3::hash(b"othertesthash"));
    let t0 = [0, 1, 2, 3];
    let t1 = [0, 1, 2, 3, 4];
    let t2 = [0, 1, 5, 6, 7];
    let t3 = [0, 1, 8, 9, 10];
    let t4 = [0, 1, 5, 6, 7];
    let t5 = [0, 1, 2, 6, 7];
    let t6 = [0, 2, 3, 6, 7];
    let t7 = [0, 3, 4, 6, 10];

    FailurePointTree::add(&mut tree, &t0, t0.len(), other_hash);

    FailurePointTree::print(&tree);

    let to_be_removed_hash = FailurePointTree::add(&mut tree, &t1, t1.len(), hash);
    FailurePointTree::add(&mut tree, &t2, t2.len(), hash);
    FailurePointTree::add(&mut tree, &t3, t3.len(), hash);
    FailurePointTree::add(&mut tree, &t4, t4.len(), hash);
    FailurePointTree::add(&mut tree, &t5, t5.len(), hash);
    FailurePointTree::add(&mut tree, &t6, t6.len(), hash);
    FailurePointTree::add(&mut tree, &t7, t7.len(), hash);

    FailurePointTree::print(&tree);

    println!("\n\nMarking first branch containing address 7 as visited:\n");
    let leaf = FailurePointTree::search(&tree, 7);
    FailurePointTree::mark_visited(&mut tree, leaf);
    FailurePointTree::print(&tree);

    println!("\n\nMark path {:?} as visted:\n", &t7);
    let leaf = FailurePointTree::get_by_addrs(&mut tree, &t7, t7.len());
    FailurePointTree::mark_visited(&mut tree, leaf);
    FailurePointTree::print(&tree);

    println!("\n\nCheck if tree contains a specific leaf and get it's path:\n");
    let path = FailurePointTree::get_path_from_addr(&tree, leaf);
    if let Ok(x) = FailurePointTree::contains(&tree, &t7, t7.len()) {
        println!("Path Check: {}", x);
    }
    let leaf_addr;
    let visited;
    unsafe {
        leaf_addr = FPTraceAddr::get_addr(&*leaf.unwrap().as_ptr());
        visited = if FPTraceAddr::is_visited(&*leaf.unwrap().as_ptr()) {
            "visited"
        } else {
            "unvisted"
        };
    };
    println!(
        "Path to {} leaf with addr {:?}: {:?}",
        visited, leaf_addr, &path
    );

    if let Some(x) = to_be_removed_hash {
        println!("t0 {:?} Hash: {:?}", t0, other_hash);
        println!("t1 {:?} Hash: {:?}", t1, hash);
        println!("Hash to remove after inserting t1 into t0: {:?}", x);
    } else {
        println!("Crash Image is None");
    }
}
