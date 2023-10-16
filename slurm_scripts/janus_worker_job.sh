#!/bin/bash
#
#SBATCH --job-name=janus-worker
#SBATCH --partition="standard"
#
#SBATCH --cpus-per-task=1

set -eu

if [ -z ${1+x} ] || [ -z ${2+x} ]; then
    echo "Invalid number of args"
    exit 1
fi

CMD=$1
WORKERBIN=$2
SCRATCHDIR=$3

export RAYON_NUM_THREADS=1

# Workers have a local scratch space that stores Groth16 keys and
# coordinator requests
BENCH_DESC=$(basename "$SCRATCHDIR")
LOCAL_SCRATCHDIR="/tmp/${USER}-${BENCH_DESC}"

# Responses are written to scratch
RESPDIR="$SCRATCHDIR/resps"

# Requests are stored locally and synced in ./janus_startup_cache
REQDIR="$LOCAL_SCRATCHDIR/reqs"

# Only RESPDIR might not exist already
mkdir -p "$RESPDIR"

# The subcircuit ID is the task ID (minus 1 because 0-indexing)
SUBCIRCUIT_IDX="$((SLURM_ARRAY_TASK_ID-1))"

echo -n "BEGINTIME "
date +%s

if [ $CMD = "stage0" ]; then
	PKDIR="$LOCAL_SCRATCHDIR/g16_cks"
	/usr/bin/time ./janus_startup_cache.sh ck $BENCH_DESC
elif [ $CMD = "stage1" ]; then
	PKDIR="$LOCAL_SCRATCHDIR/g16_pks"
	/usr/bin/time ./janus_startup_cache.sh pk $BENCH_DESC
else
	echo "invalid command $CMD"
	exit 1
fi

# If the command is "stage0" then process the corresponding stage0 request
if [ $CMD = "stage0" ]; then
	echo "Processing stage0 req #$SUBCIRCUIT_IDX"
	"$WORKERBIN" process-stage0-request \
		--g16-pk-dir "$PKDIR" \
		--req-dir "$REQDIR" \
		--resp-dir "$RESPDIR" \
		--subcircuit-index $SUBCIRCUIT_IDX
elif [ $CMD = "stage1" ]; then
	# If the command is "stage1" then process the corresponding stage1 request
	echo "Processing stage1 req #$SUBCIRCUIT_IDX"
	"$WORKERBIN" process-stage1-request \
		--g16-pk-dir "$PKDIR" \
		--req-dir "$REQDIR" \
		--resp-dir "$RESPDIR" \
		--subcircuit-index $SUBCIRCUIT_IDX
else
	echo "invalid command $CMD"
	exit 1
fi

echo -n "ENDTIME "
date +%s
