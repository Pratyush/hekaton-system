#!/bin/bash

set -eu

KEYFILE_PATH=$1
NUM_WORKERS=$2
CPUS_PER_WORKER=$3

export RAYON_NUM_THREADS=$CPUS_PER_WORKER

FILENAME=$(basename $KEYFILE_PATH)
cp $KEYFILE_PATH /tmp/$FILENAME

module load openmpi
mpirun -n $(($NUM_WORKERS + 1)) \
	node work \
	--key-file $KEYFILE_PATH \
	--num-workers $NUM_WORKERS \
