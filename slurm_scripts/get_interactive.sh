#!/bin/bash
srun --nodes=1 --ntasks-per-node=1 --time=01:00:00 --pty --constraint="Xeon&4216" bash -i
#srun --nodes=1 --ntasks-per-node=1 --time=01:00:00 --pty --constraint="E5-2620" bash -i
