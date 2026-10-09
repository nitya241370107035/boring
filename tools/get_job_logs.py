import urllib.request
import json

runs_url = "https://api.github.com/repos/nitya241370107035/boring/actions/runs"
req = urllib.request.Request(runs_url, headers={"User-Agent": "Mozilla/5.0"})
with urllib.request.urlopen(req) as resp:
    runs = json.loads(resp.read().decode()).get("workflow_runs", [])
    if not runs:
        print("No runs found")
        exit(0)
    latest_run = runs[0]
    print(f"Latest Run ID: {latest_run['id']}, Status: {latest_run['status']}, Conclusion: {latest_run['conclusion']}")

jobs_url = latest_run["jobs_url"]
j_req = urllib.request.Request(jobs_url, headers={"User-Agent": "Mozilla/5.0"})
with urllib.request.urlopen(j_req) as j_resp:
    jobs = json.loads(j_resp.read().decode()).get("jobs", [])
    for job in jobs:
        print(f"Job: {job['name']} (ID: {job['id']})")
        for s in job.get("steps", []):
            print(f"  Step: {s['name']} -> {s['conclusion']}")
