#!/bin/bash

set -u

# Parameters: $1 (first command line arg) is the number of tasks to be run labeled [1-$1].

COORDBIN="/home/micro/horizontally-scalable-snarks-system/target/release/coordinator"
WORKERBIN="/home/micro/horizontally-scalable-snarks-system/target/release/worker"
#TOPSCRATCHDIR="/fs/nexus-scratch/micro"
TOPSCRATCHDIR="/scratch/zt1/project/imiers-prj/shared/"

MEM_PER_CPU="7600M"
CPUS_PER_TASK="16"

SACCT_EXTRA_ARGS="-P --delimiter=, --format=jobid,jobname,account,state,elapsedraw,cputimeraw,totalcpu,maxvm,maxrss,maxdiskread,maxdiskwrite"

HELPSTR="\
Usage:\n\
    janus_bench <benchdir> <max_num_tasks>\
"

if [ -z ${1+x} ] || [ -z ${2+x} ]; then
    echo -e "$HELPSTR"
    exit 1
fi

BENCHDIR=$1
MAXNUMTASKS=$2

# Get the bench descriptor by cutting everything in the benchname before '-'
BENCH_DESC=$(basename "$BENCHDIR" | cut -d'-' -f1)

# Make a directory in scratch space specifically for this parameter set
SCRATCHDIR="$TOPSCRATCHDIR/$BENCH_DESC"
# Local scratch space
LOCAL_SCRATCHDIR="/tmp/${USER}-${BENCH_DESC}"
mkdir -p $LOCAL_SCRATCHDIR

PKDIR="$SCRATCHDIR/g16_pks"
STATEDIR="$SCRATCHDIR/coord_state"
REMOTE_REQDIR="$SCRATCHDIR/reqs"
REMOTE_RESPDIR="$SCRATCHDIR/resps"
LOCAL_REQDIR="$LOCAL_SCRATCHDIR/reqs"
LOCAL_RESPDIR="$LOCAL_SCRATCHDIR/resps"
LOCAL_LOGDIR="$LOCAL_SCRATCHDIR/logs"
WORKER_LOGDIR="$BENCHDIR/worker_logs"

mkdir -p "$PKDIR"
mkdir -p "$STATEDIR"
mkdir -p "$REMOTE_REQDIR"
mkdir -p "$REMOTE_RESPDIR"
mkdir -p "$LOCAL_REQDIR"
mkdir -p "$LOCAL_RESPDIR"
mkdir -p "$LOCAL_LOGDIR"
mkdir -p "$WORKER_LOGDIR"

# Get number of subcircuits. This is the same as the number of G16 proving keys
NUM_SUBCIRCUITS=$(ls "$PKDIR"/g16_pk* | wc -l)

echo "Worker mem per CPU: $MEM_PER_CPU"
echo "Worker cores per task: $CPUS_PER_TASK"
echo "Max. simultaneous worker tasks: $MAXNUMTASKS"
echo ""

# Coordinator creates stage0 requests
echo "Building stage0 requests..."

# Log a timestamp
echo -n "BEGIN START-STAGE0 "
date +%s

echo -n "Groth16 PK bytelen "
du -b "$PKDIR/g16_pk_0.bin" | cut -f1

$COORDBIN start-stage0 \
	--coord-state-dir "$STATEDIR" \
	--req-dir "$LOCAL_REQDIR" \
|| { echo "FAILED"; exit 1; }

echo "Stage0 req bytelens"
du -b $LOCAL_REQDIR/stage0_req*.bin

# Log a timestamp
echo -n "END START-STAGE0 "
date +%s
echo ""

# Sync reqs and logs
echo -n "Writing stage0 requests to scratch... "
/usr/bin/time -f "%E" -o /dev/stdout rsync -aq "$LOCAL_REQDIR/" "$REMOTE_REQDIR/"

echo "Waiting for stage0 responses..."

SBATCH_STDOUT=$(\
sbatch --wait \
	--array="1-$NUM_SUBCIRCUITS%$MAXNUMTASKS" \
	--time=1:00 \
	--mem-per-cpu=$MEM_PER_CPU \
	--cpus-per-task=$CPUS_PER_TASK \
	--output="$WORKER_LOGDIR/stage0_out_%a.txt" \
	--error="$WORKER_LOGDIR/stage0_err_%a.txt" \
       	janus_worker_job.sh stage0 "$WORKERBIN" "$SCRATCHDIR" \
) || { echo "FAILED"; exit 1; }
JOB_ID=$(echo ${SBATCH_STDOUT} | grep -Po "\\d+")
sacct -j $JOB_ID $SACCT_EXTRA_ARGS > "$LOCAL_LOGDIR/stage0_metrics.txt"

echo "Building stage1 requests..."

# Sync responses and logs
echo -n "Reading stage0 responses from scratch... "
/usr/bin/time -f "%E" -o /dev/stdout rsync -aq "$REMOTE_RESPDIR/" "$LOCAL_RESPDIR/"
rsync -aq "$LOCAL_LOGDIR/" "$BENCHDIR/"

# Log a timestamp
echo ""
echo -n "BEGIN START-STAGE1 "
date +%s

echo -n "Stage0 resp bytelen "
du -b "$LOCAL_RESPDIR/stage0_resp_0.bin" | cut -f1

$COORDBIN start-stage1 \
	--resp-dir "$LOCAL_RESPDIR" \
	--coord-state-dir "$STATEDIR" \
	--req-dir "$LOCAL_REQDIR" \
|| { echo "FAILED"; exit 1; }

echo -n "Stage1 req bytelen "
du -b "$LOCAL_REQDIR/stage1_req_0.bin" | cut -f1

echo -n "END START-STAGE1 "
date +%s
echo ""

# Sync requests
echo -n "Writing stage1 requests to scratch... "
/usr/bin/time -f "%E" -o /dev/stdout rsync -aq "$LOCAL_REQDIR/" "$REMOTE_REQDIR/"

echo "Waiting for stage1 responses (this may take a while)..."
SBATCH_STDOUT=$(\
sbatch --wait \
	--array="1-$NUM_SUBCIRCUITS%$MAXNUMTASKS" \
	--time=05:00 \
	--mem-per-cpu=$MEM_PER_CPU \
	--cpus-per-task=$CPUS_PER_TASK \
	--output="$WORKER_LOGDIR/stage1_out_%a.txt" \
	--error="$WORKER_LOGDIR/stage1_err_%a.txt" \
	janus_worker_job.sh stage1 "$WORKERBIN" "$SCRATCHDIR" \
) || { echo "FAILED"; exit 1; }
JOB_ID=$(echo ${SBATCH_STDOUT} | grep -Po "\\d+")
sacct -j $JOB_ID $SACCT_EXTRA_ARGS > "$LOCAL_LOGDIR/stage1_metrics.txt"

# Sync responses and logs
echo -n "Reading stage1 responses from scratch... "
/usr/bin/time -f "%E" -o /dev/stdout rsync -aq "$REMOTE_RESPDIR/" "$LOCAL_RESPDIR/"
rsync -aq "$LOCAL_LOGDIR/" "$BENCHDIR/"

echo -n "BEGIN AGG "
date +%s

echo "Aggregating proofs"
$COORDBIN end-proof \
	--resp-dir "$LOCAL_RESPDIR" \
   	--coord-state-dir "$STATEDIR" \
|| { echo "FAILED"; exit 1; }

echo -n "Stage1 resp bytelen "
du -b "$LOCAL_RESPDIR/stage1_resp_0.bin" | cut -f1

echo -n "Agg bytelen "
du -b "$STATEDIR/agg_proof.bin" | cut -f1

echo -n "END AGG "
date +%s
echo ""

# Sync logs
rsync -aq "$LOCAL_LOGDIR/" "$BENCHDIR/"

echo "Done"
