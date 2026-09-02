#!/usr/bin/env python3
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import concurrent.futures
import json
import os
import subprocess
import sys
import threading
import time

COS_X86_IMAGES = [
    ("projects/cos-cloud/global/images/cos-125-19216-104-133", "1.34"),
    ("projects/cos-cloud/global/images/cos-125-19216-395-7", "1.35"),
    ("projects/cos-cloud/global/images/cos-129-19506-224-80", "1.36"),
]

UBUNTU_X86_IMAGES = [
    ("projects/ubuntu-os-gke-cloud/global/images/ubuntu-gke-2404-1-34-amd64-v20260130", "1.34"),
    ("projects/ubuntu-os-gke-cloud/global/images/ubuntu-gke-2404-1-35-amd64-v20260518", "1.35"),
    ("projects/ubuntu-os-gke-cloud/global/images/ubuntu-gke-2404-1-36-amd64-v20260616", "1.36"),
]

COS_ARM64_IMAGES = [
    ("projects/cos-cloud/global/images/cos-arm64-125-19216-532-62", "1.34"),
    ("projects/cos-cloud/global/images/cos-arm64-129-19506-299-82", "1.36"),
]

UBUNTU_ARM64_IMAGES = [
    ("projects/ubuntu-os-gke-cloud/global/images/ubuntu-gke-2404-1-34-arm64-v20260805", "1.34"),
    ("projects/ubuntu-os-gke-cloud/global/images/ubuntu-gke-2404-1-35-arm64-v20260804", "1.35"),
    ("projects/ubuntu-os-gke-cloud/global/images/ubuntu-gke-2404-1-36-arm64-v20260805", "1.36"),
]

ALL_IMAGES = COS_X86_IMAGES + UBUNTU_X86_IMAGES + COS_ARM64_IMAGES + UBUNTU_ARM64_IMAGES

completed_counter = 0
counter_lock = threading.Lock()

def increment_completed():
    global completed_counter
    with counter_lock:
        completed_counter += 1
        return completed_counter

def run_image_test(image, project, zone, gke_ver, idx, total):
    """Runs go run main.go for a specific image, capturing output and measuring duration."""
    start_time = time.time()

    # Determine correct machine type based on architecture
    machine_type = "e2-medium"
    if "arm64" in image or "arm" in image:
        machine_type = "t2a-standard-1"

    cmd = [
        "go", "run", "main.go",
        "-provision-vm=true",
        f"-gcp-project={project}",
        f"-gcp-zone={zone}",
        f"-machine-type={machine_type}",
        f"-source-image={image}",
        f"-gke-version={gke_ver}"
    ]
    print(f"[RUNNING {idx}/{total}] Started certification suite for: {image}")
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=True)
        duration = time.time() - start_time
        done = increment_completed()
        print(f"  [PASS {done}/{total}] Completed {image} in {duration:.1f}s")
        return image, "PASS", duration, res.stdout
    except subprocess.CalledProcessError as e:
        duration = time.time() - start_time
        done = increment_completed()
        print(f"  [FAIL {done}/{total}] Failed {image} in {duration:.1f}s")
        return image, f"FAIL (Exit code {e.returncode})", duration, e.stdout
    except Exception as e:
        duration = time.time() - start_time
        done = increment_completed()
        print(f"  [FAIL {done}/{total}] Exception on {image} in {duration:.1f}s: {e}")
        return image, f"FAIL ({e})", duration, str(e)

def main():
    parser = argparse.ArgumentParser(description="Parallel E2E Certification Runner")
    parser.add_argument("--gcp-project", help="GCP project ID to provision VMs and run tests")
    parser.add_argument("--gcp-zone", default="us-central1-b", help="GCP zone to run tests (default: us-central1-b)")
    args = parser.parse_args()

    # 1. Resolve GCP Project from argument or active gcloud config
    project = args.gcp_project
    if not project:
        try:
            project = subprocess.check_output(
                ["gcloud", "config", "get-value", "project"], text=True
            ).strip()
        except Exception:
            pass

    if not project:
        print("ERROR: No GCP project specified. Please set the --gcp-project flag or activate a gcloud project.")
        print("Usage: ./e2e/run_e2e.py --gcp-project=my-project-id")
        sys.exit(1)

    # 2. Resolve zone from argument
    zone = args.gcp_zone

    print("=================================================================")
    print("GKE Guest OS Image Certification Suite - Parallel E2E Test Runner")
    print(f"Project   : {project}")
    print(f"Zone      : {zone}")
    print(f"Workers   : {len(ALL_IMAGES)} (Fully Concurrent)")
    print("=================================================================\n")

    e2e_start_time = time.time()
    results = {}
    failed = False

    # 3. Execute all image certifications in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(ALL_IMAGES)) as executor:
        futures = {
            executor.submit(run_image_test, img, project, zone, ver, i + 1, len(ALL_IMAGES)): img
            for i, (img, ver) in enumerate(ALL_IMAGES)
        }
        for future in concurrent.futures.as_completed(futures):
            image, status, duration, logs = future.result()
            results[image] = (status, duration, logs)
            if "FAIL" in status:
                failed = True

    e2e_total_duration = time.time() - e2e_start_time

    # 4. Consolidated E2E report
    print("\n============================== E2E PARALLEL RUN SUMMARY ==============================")
    for img, ver in ALL_IMAGES:
        status, duration, _ = results[img]
        print(f"{img:<72} : {status:<15} ({duration:.1f}s)")
    print("======================================================================================")

    # 5. Output failing logs for deep diagnostics
    if failed:
        print("\n------------------------------ FAILING INSTANCES LOGS ------------------------------")
        for img, ver in ALL_IMAGES:
            status, _, logs = results[img]
            if "FAIL" in status:
                print(f"\n>>> Failure logs for image: {img} <<<\n")
                print(logs)
                print("--------------------------------------------------------------------------------")

    minutes = int(e2e_total_duration // 60)
    seconds = int(e2e_total_duration % 60)
    print(f"\nTotal E2E Parallel Execution Time: {minutes} minutes and {seconds} seconds ({e2e_total_duration:.1f}s)")

    if failed:
        print("E2E verification completed with failures.")
        sys.exit(1)

    print("All parallel E2E certifications passed successfully!")
    sys.exit(0)

if __name__ == "__main__":
    main()
