#!/bin/bash

set -eu

MEM_PER_CPU="3800M"
CPUS_PER_TASK="16"

HELPSTR="\
Usage:\n\
setup_bench <num_subcircuits> <num_sha2_iters> <num_portals>\
"

if [ -z ${1+x} ] || [ -z ${2+x} ] || [ -z ${3+x} ]; then
    echo -e "$HELPSTR"
    exit 1
fi

NUM_SUBCIRCUITS=$1
NUM_SHA2_ITERS=$2
NUM_PORTALS=$3

# nc=num subcircuits, ns=num sha2 iters, np=num portals
JOB_DESC="nc=${NUM_SUBCIRCUITS}_ns=${NUM_SHA2_ITERS}_np=${NUM_PORTALS}"
OUT_FILENAME="pks-${JOB_DESC}.bin"

env RUSTFLAGS="-Awarnings" cargo build --release --features parallel
../target/release/node setup \
	--num-subcircuits $NUM_SUBCIRCUITS \
	--num-sha2-iters $NUM_SHA2_ITERS \
	--num-portals $NUM_PORTALS \
	--key-out $OUT_FILENAME
