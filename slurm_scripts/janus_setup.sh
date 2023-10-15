#!/bin/bash

set -euf

# Parameters: $1 (first command line arg) is the number of tasks to be run labeled [1-$1].

COORDBIN="/home/micro/horizontally-scalable-snarks-system/target/release/coordinator"
#TOPSCRATCHDIR="/fs/nexus-scratch/micro"
TOPSCRATCHDIR="/scratch/zt1/project/imiers-prj/shared/"

HELPSTR="\
Usage:\n\
janus_setup <num_circuits> <num_sha2_iters_per_subcircuit> <num_portals_per_subcircuit>\
"

if [ -z ${1+x} ] || [ -z ${2+x} ] || [ -z ${3+x} ]; then
    echo -e "$HELPSTR"
    exit 1
fi

NUM_SUBCIRCUITS=$1
NUM_SHA2_ITERS=$2
NUM_PORTALS=$3

# Generate a bench directory
DATETIME=$(printf '%(%Y%m%d.%H%M%S)T\n' -1)
# nc=num subcircuits, ni=num sha2 iters, np=num portals
BENCHDIR="bench_nc${NUM_SUBCIRCUITS}_ni${NUM_SHA2_ITERS}_np${NUM_PORTALS}-$DATETIME"

# Get the bench descriptor by cutting everything in the benchname before '-'. Now
# we can reuse a setup for multiple bench runs of the same parameters
BENCH_DESC=$(basename "$BENCHDIR" | cut -d'-' -f1)

echo "Creating bench directory $BENCHDIR. Give this to janus_bench when you call it"
mkdir $BENCHDIR

# Make a directory in scratch space specifically for this parameter set
SCRATCHDIR="$TOPSCRATCHDIR/$BENCH_DESC"
mkdir -p "$SCRATCHDIR"

# Now make subdirectories for different items
PKDIR="$SCRATCHDIR/g16_pks"
STATEDIR="$SCRATCHDIR/coord_state"

mkdir -p "$PKDIR"
mkdir -p "$STATEDIR"

echo "Generating keys..."
"$COORDBIN" gen-keys \
	--g16-pk-dir "$PKDIR" \
	--coord-state-dir "$STATEDIR" \
	--num-subcircuits $NUM_SUBCIRCUITS \
	--num-sha2-iters $NUM_SHA2_ITERS \
	--num-portals $NUM_PORTALS
