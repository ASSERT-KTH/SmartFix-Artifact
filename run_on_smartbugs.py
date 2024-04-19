import csv
import os
import subprocess
import sys
import json
import time
from multiprocessing import Pool

def get_mid_dir(path):
    path_components = path.split(os.path.sep)
    filename = path_components[-1]
    return path_components[-2], filename.split(".")[0]

def run_smartfix(path, contract, outdir):
    REPAIR_LOOP_TIMEOUT = '5400'
    REPAIR_TOOL_TIMEOUT = '150'
    Z3_TIMEOUT = '20000'
    command = f"./main.native -input {path} -mode repair -outdir {outdir} -main {contract} -repair_loop_timeout {REPAIR_LOOP_TIMEOUT} -repair_tool_timeout {REPAIR_TOOL_TIMEOUT} -z3timeout {Z3_TIMEOUT}"

    start_time = time.time()
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=60*20)
    except subprocess.TimeoutExpired:
        return -1, -1, -1, -1
    elapsed_time = time.time() - start_time
    return result.returncode, elapsed_time, result.stdout, result.stderr

def write_results(results_csv, res):
    with open(results_csv, 'w', newline='') as csvfile:
        for r in res:
            fieldnames = ['path', 'contract', 'elapsed_time', 'return_code']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writerow({
                    'path': r[0],
                    'contract': r[1],
                    'elapsed_time': r[2],
                    'return_code': r[3]
                })

def process_entry(path, contract, outdir):

    mid, file = get_mid_dir(path)
    outdir = os.path.join(outdir, mid)
    os.makedirs(outdir, exist_ok=True)
    outdir = os.path.join(outdir, file)
    return_code, elapsed_time, stdout, stderr = run_smartfix(path, contract, outdir)

    return path, contract, elapsed_time, return_code, stdout, stderr

def get_args(smartbugs_dir, output_dir):
    args = []

    vuln_json = smartbugs_dir + "/vulnerabilities.json"
    with open(vuln_json, 'r') as file:
        data = json.load(file)

    for entry in data:
        path = smartbugs_dir + "/" + entry.get('path')
        contract = entry.get('contract_names')[0]
        args.append((path, contract, output_dir))

    return args

def write_log(res, output_dir):
    for r in res:
        stdout = r[4]
        stderr = r[5]
        path = r[0]
        mid, file = get_mid_dir(path)
        outdir = os.path.join(output_dir, mid)
        outdir = os.path.join(outdir, file)
        os.makedirs(outdir, exist_ok=True)
        stdout_file = os.path.join(outdir, file+ ".out")
        stderr_file = os.path.join(outdir, file+ ".log")
        with open(stdout_file, 'w') as file:
            file.write(stdout)
        with open(stderr_file, 'w') as file:
            file.write(stderr)


def main():

    if len(sys.argv) != 4:
        print("Usage: python run_on_smartbugs.py <smartbugs_directory> <output_directory> <number_of_processes>")
        sys.exit(1)

    smartbugs_dir = sys.argv[1]
    output_dir = sys.argv[2]
    processes = int(sys.argv[3])

    # Load JSON file
    vuln_json = smartbugs_dir + "/vulnerabilities.json"
    with open(vuln_json, 'r') as file:
        data = json.load(file)

    with Pool(processes) as pool:
        res = pool.starmap(process_entry, get_args(smartbugs_dir, output_dir))
    
    write_log(res, output_dir)
    csv_file = os.path.join(output_dir, 'results.csv')
    write_results(csv_file, res)
    

if __name__ == "__main__":
    main()