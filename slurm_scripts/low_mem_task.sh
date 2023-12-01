#!/bin/bash

KEYFILE_PATH=$1
NUM_CONCURRENT_PROOFS=$2

/home/micro/horizontally-scalable-snarks-system/target/release/all_in_one \
	--key-file $KEYFILE_PATH \
	--num-concurrent-proofs $NUM_CONCURRENT_PROOFS
