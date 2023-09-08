use vinter_trace2img::FailurePointTree;

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

    println!("t1 ({:?}) return status: {}", &t1, tree.add(&t1, t1.len()));
    println!("t2 ({:?}) return status: {}", &t2, tree.add(&t2, t2.len()));
    println!("t3 ({:?}) return status: {}", &t3, tree.add(&t3, t3.len()));
    println!("t4 ({:?}) return status: {}", &t4, tree.add(&t4, t4.len()));
    println!("t5 ({:?}) return status: {}", &t5, tree.add(&t5, t5.len()));
    println!("t6 ({:?}) return status: {}", &t6, tree.add(&t6, t6.len()));
    println!("t7 ({:?}) return status: {}", &t7, tree.add(&t7, t7.len()));
    println!("t8 ({:?}) return status: {}", &t8, tree.add(&t8, t8.len()));
    tree.print();

    println!("\n\nMarking first branch containing address 7 as visited:\n");
    let leaf = tree.search(7);
    tree.mark_visited(leaf);
    tree.print();

    println!("\n\nMark path {:?} as visted:\n", &t7);
    let leaf = tree.get_by_addrs(&t7, t7.len());
    tree.mark_visited(leaf);
    tree.print();

    println!("\n\nCheck if tree contains a specific leaf and get it's path:\n");
    let path = tree.get_path_from_addr(leaf);
    if let Ok(x) = tree.contains(&t7, t7.len()) {
        println!("Path Contained: {}", x);
    }
    let leaf_addr;
    let visited;
    unsafe {
        leaf_addr = leaf.unwrap().as_ref().get_addr();
        visited = if leaf.unwrap().as_ref().is_visited() {
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
