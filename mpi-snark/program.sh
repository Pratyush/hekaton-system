#!/bin/bash
#python3 ./iansBadPythonScript.py $@
 echo "numCPUs: `nproc` . Command line arguments:" $@
../target/release/node work $@
#./scatter-gather