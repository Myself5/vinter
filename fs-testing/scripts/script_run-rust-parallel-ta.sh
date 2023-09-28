#!/usr/bin/env bash
set -eu -o pipefail

script=$0
scriptdir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
base=$scriptdir/../..
fs_dir=$scriptdir/..
results=results/run_rust_parallel_all

rm -f $results/rust_parallel_ta_results.json
vms=("vm_pmfs" "vm_nova" "vm_nova-protection")

declare -A vmlinuxmap
vmlinuxmap["vm_pmfs"]="$fs_dir/linux/pmfs_build/vmlinux"
vmlinuxmap["vm_nova"]="$fs_dir/linux/nova_build/vmlinux"
vmlinuxmap["vm_nova-protection"]="$fs_dir/linux/nova_build/vmlinux"

usage() {
    echo "Usage: $script [options]"
    echo "Options:"
    echo " -(j)son: Create a JSON output instead of the default, human readable text"
    echo " -(v)erbose: Show verbose duration timings (always included in json)"
    echo " -(k)ernel: Read and use vmlinux image specified in the vm.yaml"
}

use_and_parse_json=false
use_and_read_vmlinux=false
options=()
vmlinux_param=""

while [[ "${1-}" = -* ]]; do
    case "$1" in
    -j | --json)
        use_and_parse_json=true
        echo "" >$results/rust_parallel_ta_results.json
        ;;
    -v | --verbose)
        options+=("--verbose")
        ;;
    -k | --kernel)
        use_and_read_vmlinux=true
        ;;
    --help | -h | *)
        usage
        exit 0
        ;;
    esac

    shift
done

for vm in "${vms[@]}"; do
    if [ "$use_and_read_vmlinux" = true ]; then
        vmlinux_param="--vmlinux ${vmlinuxmap["$vm"]}"
    fi

    if [ "$use_and_parse_json" = true ]; then
        jq -n ".${vm//[^[:alnum:]]/_} |= {results:[]}" >$results/empty_vm.json

        jq -s "add" $results/rust_parallel_ta_results.json $results/empty_vm.json >$results/rust_parallel_ta_results.json.tmp && mv $results/rust_parallel_ta_results.json.tmp $results/rust_parallel_ta_results.json

        find "$results/$vm/" -name "trace.bin" | xargs -Itrace dirname trace | xargs -Ipath bash -c "outdir=\"path\"; test=\"\$(basename \"\$outdir\")\"; json=\$(\"$base/target/release/vinter_report\" analyze-trace ${options[@]} -j --output-dir \"\$outdir/\" ${vmlinux_param} \"\$outdir/trace.bin\" | sed 's/\"/\\\"/g' | jq '{\"test\": \"'\$test'\", \"vm\": \"'$vm'\"} + .') && json=\$(echo \$json | tr -d ' ') && echo \$json && jq \".${vm//[^[:alnum:]]/_}.results += [\"\$json\"]\" $results/rust_parallel_ta_results.json > $results/rust_parallel_ta_results.json.tmp && mv $results/rust_parallel_ta_results.json.tmp $results/rust_parallel_ta_results.json"

        t=$(jq "[.${vm//[^[:alnum:]]/_} | .results[] | .ta_bugs] | reduce .[] as \$num (0; .+\$num)" $results/rust_parallel_ta_results.json)

        e=$(jq "[.${vm//[^[:alnum:]]/_} | .results[] | .ta_entries] | reduce .[] as \$num (0; .+\$num)" $results/rust_parallel_ta_results.json)

        f=$(jq "[.${vm//[^[:alnum:]]/_} | .results[] | .total_ms] | reduce .[] as \$num (0; .+\$num)" $results/rust_parallel_ta_results.json)

        jq ".${vm//[^[:alnum:]]/_} += {ta_bugs: $t,ta_entries: $e,full_run_ms: $f}" $results/rust_parallel_ta_results.json >$results/rust_parallel_ta_results.json.tmp && mv $results/rust_parallel_ta_results.json.tmp $results/rust_parallel_ta_results.json

        sorted_results=$(jq ".${vm//[^[:alnum:]]/_}.results | sort_by(.test)" $results/rust_parallel_ta_results.json)

        jq ".${vm//[^[:alnum:]]/_}.results = $sorted_results" $results/rust_parallel_ta_results.json >$results/rust_parallel_ta_results.json.tmp && mv $results/rust_parallel_ta_results.json.tmp $results/rust_parallel_ta_results.json
    else
        find "$results/$vm/" -name "trace.bin" | xargs -Itrace dirname trace | xargs -Ipath -P "$parallel" bash -c "outdir=\"path\"; test=\"\$(basename \"\$outdir\")\"; \"$base/target/release/vinter_report\" analyze-trace ${options[@]} --output-dir \"\$outdir/\" ${vmlinux_param} \"\$outdir/trace.bin\""
    fi
done
