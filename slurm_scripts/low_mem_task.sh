#!/bin/bash

KEYFILE_PATH=$1
NUM_CORES_TO_USE=$2

export RAYON_NUM_THREADS=$NUM_CORES_TO_USE


/home/micro/horizontally-scalable-snarks-system/target/release/all_in_one \
	--key-file $KEYFILE_PATH \
