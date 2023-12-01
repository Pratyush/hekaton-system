#!/bin/bash

NUM_SUBCIRCUITS=$1
NUM_SHA2_ITERS=$2
NUM_PORTALS=$3
KEYFILE_OUT=$4

module load openmpi
/home/micro/horizontally-scalable-snarks-system/target/release/node setup \
	--num-subcircuits $NUM_SUBCIRCUITS \
	--num-sha2-iters $NUM_SHA2_ITERS \
	--num-portals $NUM_PORTALS \
	--key-out $KEYFILE_OUT
