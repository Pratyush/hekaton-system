#!/bin/bash

echo "Task $SLURM_PROCID is on node $SLURM_NODEID"
echo "Task $SLURM_PROCID num CPUs: $(nproc)"

export RAYON_NUM_THREADS=$3

/home/micro/horizontally-scalable-snarks-system/target/release/node \
	work \
	--key-file $1 \
	--num-workers $2 \
