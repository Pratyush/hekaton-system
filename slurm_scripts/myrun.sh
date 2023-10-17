#!/bin/bash

sbatch \
	--wait \
	--ntasks=9 \
       	--out=srun_out.txt \
	--error=srun_err.txt \
	mpirunscript.sh
