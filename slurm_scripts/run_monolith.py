#!/bin/python3

from datetime import datetime
import os
import re
import subprocess
from sys import argv, exit

# Global values
mem_per_cpu = "4000M"
tot_num_cores = "128"

# Helper function
def run(*cmd):
    return subprocess.check_output(cmd).decode("utf-8")

def run_capture_stderr(*cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode("utf-8")
    except Exception as e:
        print("Fatal error")
        exit(e.output)

# Pick the output/err filenames
timestamp = datetime.now().strftime("%Y%m%d.%H%M%S")   
out_filename = f"bench_monolith_out-{timestamp}.txt"
err_filename = f"bench_monolith_err-{timestamp}.txt"

# Find the monolithic bench binary
binary_path = None
bench_path = "/home/micro/horizontally-scalable-snarks-system/target/release/deps"
for f in os.listdir(bench_path):
    if f.startswith("monolithic") and not f.endswith(".d"):
        if binary_path is not None:
            exit("Multiple monolith binaries in target/release/deps")
        binary_path = os.path.join(bench_path, f)

# Run the job
job_out = run_capture_stderr(
    "srun",
    "--time", "15:00:00",
    "--account", "imiers-prj-cmsc",
    "--job-name", "monolith",
    "--out", out_filename,
    "--error", err_filename,
    "--ntasks", "1",
    "--exclusive",
    "--partition", "serial",
    "--mem-per-cpu", mem_per_cpu,
    "--cpus-per-task", tot_num_cores,
    binary_path
)

# Wait a sec before gathering stats
run("sleep", "1")

job_id = re.search('(\d+)', job_out).group(1).strip()
max_rss = run("sacct", "-j", job_id, "-o", "maxrss").splitlines()[-1].strip()

with open(out_filename, "a") as f:
    f.write(f"MEM PER CORE: {mem_per_cpu}\n")
    f.write(f"TOT NUM CORES: {tot_num_cores}\n")
    f.write(f"MAX RSS: {max_rss}\n")
