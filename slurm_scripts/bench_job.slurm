#!/bin/bash

set -eu

NUM_WORKERS=$1
NUM_SUBCIRCUITS=$2
NUM_SHA2_ITERS=$3
NUM_PORTALS=$4
CPUS_PER_WORKER=$5

export RAYON_NUM_THREADS=$CPUS_PER_WORKER

echo "HERE2"

module load openmpi
mpirun -n $(($NUM_WORKERS + 1)) \
	/home/micro/mpitest/node \
	--num-workers $NUM_WORKERS \
	--num-subcircuits $NUM_SUBCIRCUITS \
	--num-sha2-iters $NUM_SHA2_ITERS \
       	--num-portals $NUM_PORTALS
