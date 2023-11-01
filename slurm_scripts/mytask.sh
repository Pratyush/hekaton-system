#!/bin/bash

echo "SLURM_CPUS_ON_NODE   = " $SLURM_CPUS_ON_NODE
echo "SLURM_CPUS_PER_TASK  = " $SLURM_CPUS_PER_TASK
echo "SLURM_JOB_ID         = " $SLURM_JOB_ID
echo "SLURM_JOB_NAME       = " $SLURM_JOB_NAME
echo "SLURM_JOB_NODELIST   = " $SLURM_JOB_NODELIST
echo "SLURM_JOB_NUM_NODES  = " $SLURM_JOB_NUM_NODES
echo "SLURM_LOCALID        = " $SLURM_LOCALID
echo "SLURM_NODEID         = " $SLURM_NODEID
echo "SLURM_NTASKS         = " $SLURM_NTASKS
echo "SLURM_PROCID         = " $SLURM_PROCID
echo "SLURM_SUBMIT_DIR     = " $SLURM_SUBMIT_DIR
echo "SLURM_SUBMIT_HOST    = " $SLURM_SUBMIT_HOST
echo "SLURM_TASKS_PER_NODE = " $SLURM_TASKS_PER_NODE
echo "SLURM_MEM_PER_CPU    = " $SLURM_MEM_PER_CPU
echo "SLURM_MEM_PER_NODE   = " $SLURM_MEM_PER_NODE

echo "Task $SLURM_PROCID is on node $SLURM_NODEID"
echo "Task $SLURM_PROCID num CPUs: $(nproc)"

export RAYON_NUM_THREADS=$3

/home/micro/horizontally-scalable-snarks-system/target/release/node \
	work \
	--key-file $1 \
	--num-workers $2 \
