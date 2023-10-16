#!/bin/bash

set -euf

SACCT_EXTRA_ARGS="-P --delimiter=, --format=jobid,jobname,account,state,elapsedraw,cputimeraw,totalcpu,maxvm,maxrss,maxdiskread"

HELPSTR="\
Usage:\n\
srun_janus_setup.sh <num_circuits> <num_sha2_iters_per_subcircuit> <num_portals_per_subcircuit>\
"

if [ -z ${1+x} ] || [ -z ${2+x} ] || [ -z ${3+x} ]; then
    echo -e "$HELPSTR"
    exit 1
fi

NUM_SUBCIRCUITS=$1
NUM_SHA2_ITERS=$2
NUM_PORTALS=$3

SBATCH_STDOUT=$(\
srun --partition=standard --account=imiers-prj-cmsc \
	--time 1:00:00 --cpus-per-task=32 --ntasks=1 \
	--output="setup_out.txt" \
       	/usr/bin/time -vo "setup_timing.txt" ./janus_setup.sh $NUM_SUBCIRCUITS $NUM_SHA2_ITERS $NUM_PORTALS \
)
JOB_ID=$(echo ${SBATCH_STDOUT} | grep -Po "\\d+")

sacct- j $JOB_ID $SACCT_EXTRA_ARGS > setup_metrics.txt

echo "Wrote to setup_out.txt, setup_timing.txt, and setup_metrics.txt"
