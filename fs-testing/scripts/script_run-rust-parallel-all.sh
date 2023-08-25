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
	--help | -h | *)
		usage
		exit 0
		;;
	esac

	shift
done

for vm in "${vms[@]}"; do
	find "$scriptdir" -name "test_*.yaml" | xargs -Ipath basename path .yaml | xargs -Itestname -P "$parallel" "$base/target/release/vinter_trace2img" analyze -g${generator} --output-dir "$results/testname" "$scriptdir/$vm.yaml" "$scriptdir/testname.yaml" || true
done
