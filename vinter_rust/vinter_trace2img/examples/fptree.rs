use vinter_trace2img::{FPTraceAddr, FailurePointTree};

fn main() {
    let mut tree = FailurePointTree::new();
    println!("Creating Tree:\n");
    let t1 = [0, 1, 2, 3, 4];
    let t2 = [0, 1, 5, 6, 7];
    let t3 = [0, 1, 8, 9];
    let t4 = [0, 1, 5, 6, 7];
    let t5 = [0, 1, 2, 6, 7];
    let t6 = [0, 2, 3, 6, 7];
    let t7 = [0, 3, 4, 6];
    let t8 = [0, 3, 4, 6, 10];

    println!(
        "t1 ({:?}) return status: {}",
        &t1,
        FailurePointTree::add(&mut tree, &t1, t1.len())
    );
    println!(
        "t2 ({:?}) return status: {}",
        &t2,
        FailurePointTree::add(&mut tree, &t2, t2.len())
    );
    println!(
        "t3 ({:?}) return status: {}",
        &t3,
        FailurePointTree::add(&mut tree, &t3, t3.len())
    );
    println!(
        "t4 ({:?}) return status: {}",
        &t4,
        FailurePointTree::add(&mut tree, &t4, t4.len())
    );
    println!(
        "t5 ({:?}) return status: {}",
        &t5,
        FailurePointTree::add(&mut tree, &t5, t5.len())
    );
    println!(
        "t6 ({:?}) return status: {}",
        &t6,
        FailurePointTree::add(&mut tree, &t6, t6.len())
    );
    println!(
        "t7 ({:?}) return status: {}",
        &t7,
        FailurePointTree::add(&mut tree, &t7, t7.len())
    );
    println!(
        "t8 ({:?}) return status: {}",
        &t8,
        FailurePointTree::add(&mut tree, &t8, t8.len())
    );
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
        println!("Path Contained: {}", x);
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
}
