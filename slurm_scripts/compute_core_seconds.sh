#!/bin/bash

BENCHDIR=$1

tail -n +2 "$1/stage1_metrics.txt" | cut -d, -f5 | sort | awk '{n += $1}; END{print n}'
