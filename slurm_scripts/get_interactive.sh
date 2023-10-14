#!/bin/bash
#srun --nodes=1 --ntasks-per-node=1 --cpus-per-task=1 --time=01:00:00 --pty --partition="standard" bash -i
srun --nodes=1 --ntasks-per-node=1 --time=01:00:00 --pty --partition="scavenger" bash -i
