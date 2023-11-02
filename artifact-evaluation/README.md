# Information for Artifact Evaluation

We provide a virtual machine image for evaluating Vinter. It contains a
binaries for Vinter as well as the kernels we tested in the paper.

## Getting Started Instructions

Download the virtual machine image `vinter.qcow2` [from doi:10.5281/zenodo.6544868](https://doi.org/10.5281/zenodo.6544868).

Start the virtual machine in a suitable hypervisor. Vinter can optionally run
its analysis in parallel, so make sure to provide plenty of memory (`-m`) and
vCPUs (`-smp`). As a rough guideline, provide 2 GB of memory per vCPU. For
example with QEMU/KVM:
```
qemu-kvm -m 16G -smp 8 -display none -serial mon:stdio -device e1000,netdev=net0 \
    -netdev user,id=net0,hostfwd=tcp::2222-:22 vinter.qcow2
```

Connect to the virtual machine via SSH. The password for the users vinter and
root is "vinter". Note that the SSH server does not allow direct login as root,
use `su` instead. It is also possible to interact with the VM via the serial
console, but we strongly recommend SSH to avoid glitches.
```
ssh -p 2222 vinter@localhost
```

Inside the VM, you can find Vinter in `/home/vinter/vinter`. Before you can start,
it is required to pull the changes from this repo.

```
cd ~/vinter
git pull https://github.com/Myself5/vinter -b thesis
```

To verify that Vinter is set up correctly, we provide a script that runs Vinter
with one test case on each kernel. This will take around a minute to complete.
```
fs-testing/scripts/run-rust-single-test.sh
```

The script will put results into the directory `results/rust-single-test`. View
a short summary of these results with the following commands:
```
vinter_python/report-results.py analyze \
    results/rust-single-test/vm_nova/test_hello-world
vinter_python/report-results.py analyze \
    results/rust-single-test/vm_pmfs/test_hello-world
```

You can see that Vinter reports a violation of *single final state* for the
test on NOVA, but not on PMFS.
