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

export RAYON_NUM_THREADS=$(($CPUS_PER_WORKER + 1))

FILENAME=$(basename $KEYFILE_PATH)
ln -s ../target/$KEYFILE_PATH /tmp/$FILENAME || true

env RUSTFLAGS="-Awarnings" cargo build --release --features parallel
mpirun -n $(($NUM_WORKERS + 1)) \
	--use-hwthread-cpus \
	../target/release/node work \
	--key-file ../target/$KEYFILE_PATH \
	--num-workers $NUM_WORKERS \
