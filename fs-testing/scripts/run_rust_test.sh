#!/usr/bin/env bash
set -eu -o pipefail

script=$0
scriptdir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
base=$scriptdir/../..
results=results/rust-test

rm -rf "$results"
mkdir -p "$results"/{vinter_rust_legacy,vinter_rust}

test=test_hello-world
vms=("vm_nova" "vm_pmfs")

# Analysis with vinter_rust_legacy
for vm in "${vms[@]}"; do
  echo "Running vinter_rust_legacy with test $test on $vm..."
  "$base/target/release/vinter_trace2img_legacy" analyze --output-dir "$results/vinter_rust_legacy" \
    "$scriptdir/$vm.yaml" "$scriptdir/$test.yaml"
done

# Analysis with vinter_rust using the new crash image generator
#for vm in "${vms[@]}"; do
#  echo "Running vinter_rust with test $test on $vm..."
#  "$base/target/release/vinter_trace2img" analyze --output-dir "$results/vinter_rust" \
#    "$scriptdir/$vm.yaml" "$scriptdir/$test.yaml"
#done
