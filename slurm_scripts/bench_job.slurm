#!/bin/bash

set -eu

HELPSTR="\
Usage:\n\
bench_job.slurm <keyfile_path> <num_workers> <cores_per_task> \
"

if [ -z ${1+x} ] || [ -z ${2+x} ] || [ -z ${3+x} ]; then
    echo -e "$HELPSTR"
    exit 1
fi

KEYFILE_PATH=$1
NUM_WORKERS=$2
CORES_PER_TASK=$3

export RAYON_NUM_THREADS="$CORES_PER_TASK"

module load openmpi
#srun ./node work --key-file $KEYFILE_PATH --num-workers $NUM_WORKERS echo hello world hi
#srun ./node work --key-file $KEYFILE_PATH --num-workers $NUM_WORKERS : ./node work --key-file $KEYFILE_PATH --num-workers $NUM_WORKERS
#srun ./node work --key-file $KEYFILE_PATH \
#	--num-workers $NUM_WORKERS \
#	: \
#	./node work \
#	--key-file $KEYFILE_PATH \
#	--num-workers $NUM_WORKERS

srun ./node work --key-file $KEYFILE_PATH --num-workers $NUM_WORKERS
