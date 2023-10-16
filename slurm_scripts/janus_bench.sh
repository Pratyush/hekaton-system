#!/bin/bash

set -u

# Parameters: $1 (first command line arg) is the number of tasks to be run labeled [1-$1].

COORDBIN="/home/micro/horizontally-scalable-snarks-system/target/release/coordinator"
WORKERBIN="/home/micro/horizontally-scalable-snarks-system/target/release/worker"
#TOPSCRATCHDIR="/fs/nexus-scratch/micro"
TOPSCRATCHDIR="/scratch/zt1/project/imiers-prj/shared/"

SACCT_EXTRA_ARGS="-P --delimiter=, --format=jobid,jobname,account,state,elapsedraw,cputimeraw,totalcpu,maxvm,maxrss,maxdiskread,maxdiskwrite"

HELPSTR="\
Usage:\n\
    janus_bench <benchdir> <max_num_cores>\
"

if [ -z ${1+x} ] || [ -z ${2+x} ]; then
    echo -e "$HELPSTR"
    exit 1
fi

BENCHDIR=$1
NUMCORES=$2

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

mkdir -p "$PKDIR"
mkdir -p "$STATEDIR"
mkdir -p "$REMOTE_REQDIR"
mkdir -p "$REMOTE_RESPDIR"
mkdir -p "$LOCAL_REQDIR"
mkdir -p "$LOCAL_RESPDIR"

# Get number of subcircuits. This is the same as the number of G16 proving keys
NUM_SUBCIRCUITS=$(ls "$PKDIR"/g16_pk* | wc -l)

# Coordinator creates stage0 requests
echo "Building stage0 requests..."

# Log a timestamp
echo -n "BEGINTIME " > "$BENCHDIR/start_stage0.txt"
date +%s >> "$BENCHDIR/start_stage0.txt"

echo -n "Groth16 PK bytelen " >> "$BENCHDIR/start_stage0.txt"
du -b "$PKDIR/g16_pk_0.bin" | cut -f1 >> "$BENCHDIR/start_stage0.txt"

$COORDBIN start-stage0 \
	--coord-state-dir "$STATEDIR" \
	--req-dir "$LOCAL_REQDIR" \
	>> "$BENCHDIR/start_stage0.txt" \
|| { echo "FAILED"; exit 1; }

echo "Stage0 req bytelens" >> "$BENCHDIR/start_stage0.txt"
du -b $LOCAL_REQDIR/stage0_req*.bin >> "$BENCHDIR/start_stage0.txt"

# Log a timestamp
echo -n "ENDTIME " >> "$BENCHDIR/start_stage0.txt"
date +%s >> "$BENCHDIR/start_stage0.txt"

# Sync reqs
echo "Writing stage0 requests to scratch..."
/usr/bin/time -f "%E" -o /dev/stdout rsync -aq "$LOCAL_REQDIR/" "$REMOTE_REQDIR/"

echo "Waiting for stage0 responses..."

SBATCH_STDOUT=$(\
sbatch --wait \
	--account=imiers-prj-cmsc \
	--array="1-$NUM_SUBCIRCUITS%$NUMCORES" \
	--ntasks-per-node=128 \
	--time=1:00 \
	--output="$BENCHDIR/stage0_out_%a.txt" \
	--error="$BENCHDIR/stage0_err_%a.txt" \
       	janus_worker_job.sh stage0 "$WORKERBIN" "$SCRATCHDIR" \
) || { echo "FAILED"; exit 1; }
JOB_ID=$(echo ${SBATCH_STDOUT} | grep -Po "\\d+")
sacct -j $JOB_ID $SACCT_EXTRA_ARGS > "$BENCHDIR/stage0_metrics.txt"

echo "Building stage1 requests..."

# Sync responses
echo "Reading stage0 responses from scratch..."
/usr/bin/time -f "%E" -o /dev/stdout rsync -aq "$REMOTE_RESPDIR/" "$LOCAL_RESPDIR/"

# Log a timestamp
echo -n "BEGINTIME " >> "$BENCHDIR/start_stage1.txt"
date +%s >> "$BENCHDIR/start_stage1.txt"

echo -n "Stage0 resp bytelen " >> "$BENCHDIR/start_stage0.txt"
du -b "$LOCAL_RESPDIR/stage0_resp_0.bin" | cut -f1 >> "$BENCHDIR/start_stage0.txt"

$COORDBIN start-stage1 \
	--resp-dir "$LOCAL_RESPDIR" \
	--coord-state-dir "$STATEDIR" \
	--req-dir "$LOCAL_REQDIR" \
	> "$BENCHDIR/start_stage1.txt" \
|| { echo "FAILED"; exit 1; }

echo -n "Stage1 req bytelen " >> "$BENCHDIR/start_stage0.txt"
du -b "$LOCAL_REQDIR/stage1_req_0.bin" | cut -f1 >> "$BENCHDIR/start_stage0.txt"

echo -n "ENDTIME " >> "$BENCHDIR/start_stage1.txt"
date +%s >> "$BENCHDIR/start_stage1.txt"

# Sync requests
echo "Writing stage1 requests to scratch..."
/usr/bin/time -f "%E" -o /dev/stdout rsync -aq "$LOCAL_REQDIR/" "$REMOTE_REQDIR/"

echo "Waiting for stage1 responses (this may take a while)..."
SBATCH_STDOUT=$(\
sbatch --wait \
	--account=imiers-prj-cmsc \
	--array="1-$NUM_SUBCIRCUITS%$NUMCORES" \
	--time=03:00 \
	--mem-per-cpu=3800M \
	--ntasks-per-node=128 \
	--output="$BENCHDIR/stage1_out_%a.txt" \
	--error="$BENCHDIR/stage1_err_%a.txt" \
	janus_worker_job.sh stage1 "$WORKERBIN" "$SCRATCHDIR" \
) || { echo "FAILED"; exit 1; }
JOB_ID=$(echo ${SBATCH_STDOUT} | grep -Po "\\d+")
sacct -j $JOB_ID $SACCT_EXTRA_ARGS > "$BENCHDIR/stage1_metrics.txt"

# Sync responses
echo "Reading stage1 responses from scratch..."
/usr/bin/time -f "%E" -o /dev/stdout rsync -aq "$REMOTE_RESPDIR/" "$LOCAL_RESPDIR/"

echo -n "BEGINTIME " > "$BENCHDIR/end_proof.txt"
date +%s >> "$BENCHDIR/end_proof.txt"

echo "Aggregating proofs"
$COORDBIN end-proof \
	--resp-dir "$LOCAL_RESPDIR" \
   	--coord-state-dir "$STATEDIR" \
	>> "$BENCHDIR/end_proof.txt" \
|| { echo "FAILED"; exit 1; }

echo -n "Stage1 resp bytelen " >> "$BENCHDIR/end_proof.txt"
du -b "$LOCAL_RESPDIR/stage1_resp_0.bin" | cut -f1 >> "$BENCHDIR/end_proof.txt"

echo -n "Agg bytelen " >> "$BENCHDIR/end_proof.txt"
du -b "$STATEDIR/agg_proof.bin" | cut -f1 >> "$BENCHDIR/end_proof.txt"

echo -n "ENDTIME " >> "$BENCHDIR/end_proof.txt"
date +%s >> "$BENCHDIR/end_proof.txt"

echo "Done"
