# build panda and vinter
./build-panda.sh
./build-vinter.sh

# build kernels
# nova
git -C fs-testing/linux/nova checkout 593f927a78a6900d7cfec58199fb0a4a4fd1d646
fs-testing/linux/build-kernel.sh nova

# PMFS
# Note: Building PMFS requires gcc4, build from a suitable container. For example:
podman run --rm -v"$PWD/fs-testing/linux:/mnt" docker.io/library/gcc:4 \
sh -c 'echo "deb [check-valid-until=no] http://archive.debian.org/debian jessie-backports main\n
deb [check-valid-until=no] http://archive.debian.org/debian jessie main" > /etc/apt/sources.list &&
apt-get -o Acquire::Check-Valid-Until=false update &&
apt-get install bc -y --force-yes &&
/mnt/build-kernel.sh pmfs'