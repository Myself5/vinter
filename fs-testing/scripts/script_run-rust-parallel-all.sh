#!/usr/bin/env bash
set -eu -o pipefail

script=$0
scriptdir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
base=$scriptdir/../..
results=results

rm -rf "$results"
mkdir -p "$results"
vms=("vm_pmfs" "vm_nova" "vm_nova-protection")

usage() {
	echo "Usage: $script [options]"
	echo "Options:"
	echo " -P <num>: Analyze with <num> parallel instances (default 1)"
	echo " -g (n)one, (d)efault, (f)pt: Specify the used heuristic generator"
}

parallel=1
generator="default"
use_and_parse_json=false

while [[ "${1-}" = -* ]]; do
	case "$1" in
	-P)
		parallel=$2
		shift
		;;
	-g)
		case "$2" in
		"n" | "d" | "f" | "none" | "default" | "fpt")
			generator="$2"
			shift
			;;
		*)
			usage
			exit 0
			;;
		esac
		;;
	-j | --json)
		use_and_parse_json=true
		echo "" >$results/rust_parallel_results.json
		;;
	--help | -h | *)
		usage
		exit 0
		;;
	esac

	shift
done

for vm in "${vms[@]}"; do
	if [ "$use_and_parse_json" = true ]; then
		jq -n ".${vm//[^[:alnum:]]/_} |= {results:[]}" >$results/empty_vm.json

		jq -s "add" $results/rust_parallel_results.json $results/empty_vm.json >$results/rust_parallel_results.json.tmp && mv $results/rust_parallel_results.json.tmp $results/rust_parallel_results.json

		find "$scriptdir" -name "test_*.yaml" | xargs -Ipath basename path .yaml | xargs -Itestname -P "$parallel" "$base/target/release/vinter_trace2img" analyze -g${generator} --json --output-dir "$results/testname" "$scriptdir/$vm.yaml" "$scriptdir/testname.yaml" | tee /dev/tty | sed 's/"/\\"/g' | xargs -d'\n' -I fulljsonstring bash -c "j=\"fulljsonstring\"; jq \".${vm//[^[:alnum:]]/_}.results += [\"\$j\"]\" $results/rust_parallel_results.json > $results/rust_parallel_results.json.tmp && mv $results/rust_parallel_results.json.tmp $results/rust_parallel_results.json"

		c=$(jq "[.${vm//[^[:alnum:]]/_} | .results[] | .crash_image_duration] | reduce .[] as \$num (0; .+\$num)" $results/rust_parallel_results.json)

		s=$(jq "[.${vm//[^[:alnum:]]/_} | .results[] | .semantic_state_duration] | reduce .[] as \$num (0; .+\$num)" $results/rust_parallel_results.json)

		f=$(jq "[.${vm//[^[:alnum:]]/_} | .results[] | .total_duration] | reduce .[] as \$num (0; .+\$num)" $results/rust_parallel_results.json)

		jq ".${vm//[^[:alnum:]]/_} += {crash_image_duration: $c,semantic_state_duration: $s,full_run_duration: $f}" $results/rust_parallel_results.json >$results/rust_parallel_results.json.tmp && mv $results/rust_parallel_results.json.tmp $results/rust_parallel_results.json
	else
		find "$scriptdir" -name "test_*.yaml" | xargs -Ipath basename path .yaml | xargs -Itestname -P "$parallel" "$base/target/release/vinter_trace2img" analyze -g${generator} --output-dir "$results/testname" "$scriptdir/$vm.yaml" "$scriptdir/testname.yaml"
	fi
done
