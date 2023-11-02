#!/usr/bin/env bash
set -eu -o pipefail

script=$0
scriptdir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
base=$scriptdir/../..
results=results/rust-single-test

rm -rf "$results"
mkdir -p "$results"

test=test_hello-world
vms=("vm_nova" "vm_pmfs")

usage() {
  echo "Usage: $script [options]"
  echo "Options:"
  echo " -g (n)one, (d)efault, (f)pt: Specify the used heuristic generator"
  echo " -t <testname>: Specify the test to run. Default: test_hello-world"
  echo " -(j)son: Create a JSON output instead of the default, human readable text"
  echo " -(v)erbose: Show verbose duration timings (always included in json)"
  echo " -(k)ernel-stacktrace: Always include kernel_stacktrace in trace"
}

generator="default"
options=()

while [[ "${1-}" = -* ]]; do
  case "$1" in
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
  -t)
    test=$2
    shift
    ;;
  -j | --json)
    options+=("--json")
    ;;
  -v | --verbose)
    options+=("--verbose")
    ;;
  -k | --kernel-stacktrace)
    options+=("--kernel-stacktrace")
    ;;
  --help | -h | *)
    usage
    exit 0
    ;;
  esac

  shift
done

# Check if test exists
if [ -f "$scriptdir/$test.yaml" ]; then
  # Analysis with vinter_rust using the new crash image generator
  for vm in "${vms[@]}"; do
    echo "Running vinter_rust with test $test on $vm..."
    "$base/target/release/vinter_trace2img" analyze -g${generator} "${options[@]}" --output-dir "$results" \
      "$scriptdir/$vm.yaml" "$scriptdir/$test.yaml"
  done
else
  echo "Test: ${test} does not exist."
fi
