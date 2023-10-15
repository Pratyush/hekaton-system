#!/bin/bash
#srun --nodes=1 --ntasks-per-node=1 --cpus-per-task=1 --time=01:00:00 --pty --partition="standard" bash -i
srun --nodes=1 --account=imiers-prj-cmsc --ntasks-per-node=1 --time=01:00:00 --pty --partition="scavenger" bash -i
#srun --nodes=1 --account=imiers-prj-cmsc --ntasks-per-node=1 --time=01:00:00 --pty -w compute-b7-3 bash -i
