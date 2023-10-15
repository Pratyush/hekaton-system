#!/bin/bash

set -euf

SACCT_EXTRA_ARGS="-P --delimiter=, --format=jobid,jobname,account,state,elapsedraw,cputimeraw,totalcpu,maxvm,maxrss,maxdiskread"

HELPSTR="\
Usage:\n\
    srun_bench.sh <benchdir> <max_num_cores>\
"

if [ -z ${1+x} ] || [ -z ${2+x} ]; then
    echo -e "$HELPSTR"
    exit 1
fi

BENCHDIR=$1
NUM_CORES=$2

SBATCH_STDOUT=$(\
srun --partition=standard --time 5:00:00 --cpus-per-task=8 --mem-per-cpu=3G --account=imiers-prj-cmsc \
       	/usr/bin/time -vo "$BENCHDIR/coord_timing.txt" ./janus_bench.sh $BENCHDIR $NUM_CORES \
	> "$BENCHDIR/coord_out.txt" \
)
JOB_ID=$(echo ${SBATCH_STDOUT} | grep -Po "\\d+")

sacct- j $JOB_ID $SACCT_EXTRA_ARGS > "$BENCHDIR/coord_metrics.txt"
