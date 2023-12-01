#!/bin/python3

from datetime import datetime
import os
import re
import subprocess
from sys import argv, exit

# Global values
mem_per_cpu = "4000M"
exclusive = False

# Helper function
def run(*cmd):
    return subprocess.check_output(cmd).decode("utf-8")

def run_capture_stderr(*cmd):
    return subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode("utf-8")

exclusive_str = "--exclusive" if exclusive else ""
help_str = "\
Usage:\n\
run_low_mem <proving_keys_bin> <mem_in_gigs> <num_concurrent_proofs> \
"

if len(argv) < 4:
    exit(help_str)

# Unpack the args
keyfile_path, mem_in_gigs, num_concurrent_proofs = argv[1:]
mem_in_gigs = int(mem_in_gigs)

# Compute the necessary number of cores
assert mem_in_gigs % 4 == 0, "memory in gigabytes must be a multiple of 4"
tot_num_cores = str(mem_in_gigs // 4)

# Pick the output/err filenames
job_desc = re.search("pks-(.*?).bin", keyfile_path).group(1)
timestamp = datetime.now().strftime("%Y%m%d.%H%M%S")   
out_filename = f"bench_lowmem_out-{job_desc}-{timestamp}.txt"
err_filename = f"bench_lowmem_err-{job_desc}-{timestamp}.txt"

# Run the job
job_out = run_capture_stderr(
    "srun",
    "--time", "24:00:00",
    "--account", "imiers-prj-cmsc",
    "--job-name", job_desc,
    "--out", out_filename,
    "--error", err_filename,
    "--ntasks", "1",
    "--mem-per-cpu", mem_per_cpu,
    "--cpus-per-task", tot_num_cores,
    "/home/micro/horizontally-scalable-snarks-system/target/release/all_in_one",
    "--key-file", keyfile_path,
    "--num-concurrent-proofs", num_concurrent_proofs
)

# Wait a sec before gathering stats
run("sleep", "1")

job_id = re.search('(\d+)', job_out).group(1).strip()
max_rss = run("sacct", "-j", job_id, "-o", "maxrss").splitlines()[-1].strip()

with open(out_filename, "a") as f:
    f.write(f"JOB DESC: {job_desc}\n")
    f.write(f"MEM PER CORE: {mem_per_cpu}\n")
    f.write(f"TOT NUM CORES: {tot_num_cores}\n")
    f.write(f"NUM CONCURRENT PROOFS: {num_concurrent_proofs}\n")
    f.write(f"MAX RSS: {max_rss}\n")
    f.write(' '.join(argv))
