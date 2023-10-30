#!/bin/bash

set -eu

HELPSTR="\
Usage:\n\
bench_job.slurm <keyfile_path> <num_workers> <cores_per_worker> \
"

if [ -z ${1+x} ] || [ -z ${2+x} ] || [ -z ${3+x} ]; then
    echo -e "$HELPSTR"
    exit 1
fi

KEYFILE_PATH=$1
NUM_WORKERS=$2
CPUS_PER_WORKER=$3

export RAYON_NUM_THREADS=$CPUS_PER_WORKER

module load openmpi
module load llvm
cd /home/micro/horizontally-scalable-snarks-system/mpi-snark
env RUSTFLAGS="-Awarnings" cargo build --release --features all_parallel
cd -

mpirun -n $(($NUM_WORKERS + 1)) \
	--use-hwthread-cpus \
	/home/micro/horizontally-scalable-snarks-system/target/release/node work \
	--key-file $KEYFILE_PATH \
	--num-workers $NUM_WORKERS \
