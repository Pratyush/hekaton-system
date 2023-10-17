#!/bin/bash

module load openmpi
echo "about to run"
mpirun -n 9 /home/micro/mpitest/node --num-workers 8 --num-subcircuits 8 --num-sha2-iters 1 --num-portals 1
