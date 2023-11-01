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

echo "Job ID: $SLURM_JOB_ID"

module load openmpi

#sleep 20
srun mytask.sh $KEYFILE_PATH $NUM_WORKERS $CPUS_PER_WORKER
