#!/bin/bash
#SBATCH  --mem-per-cpu=3800M
#SBATCH --time 00:30
#SBATCH --account imiers-prj-cmsc 
#SBATCH --cpus-per-task=2  --ntasks=1 
#SBATCH hetjob
#SBATCH --cpus-per-task=1   --ntasks=32 
. ~/.bashrc
cd /home/imiers/horizontally-scalable-snarks-system/mpi-snark
pwd
module unload intel
#It is recommended that you add the exact version of the
#compiler and MPI library used when you compiled the code
#to improve long-term reproducibility
module load openmpi
module load rust
module load llvm


KEYFILE_PATH=/home/imiers/horizontally-scalable-snarks-system/mpi-snark/pks-nc=32_ns=32_np=32.bin
NUM_WORKERS=32
#module list
srun ./program.sh  --key-file $KEYFILE_PATH  --num-workers  32 : ./program.sh --key-file $KEYFILE_PATH  --num-workers  32
#srun ./bench_job.slurm : ./bench_job.slurm 

