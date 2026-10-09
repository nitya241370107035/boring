import urllib.request
import json

url = "https://api.github.com/repos/nitya241370107035/boring/actions/runs"
req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
try:
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read().decode())
        runs = data.get("workflow_runs", [])
        print(f"Total runs: {len(runs)}")
        for r in runs[:3]:
            print(f"ID: {r.get('id')} | Status: {r.get('status')} | Conclusion: {r.get('conclusion')} | URL: {r.get('html_url')}")
            # Get jobs for this run
            jobs_url = r.get("jobs_url")
            if jobs_url:
                j_req = urllib.request.Request(jobs_url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(j_req, timeout=10) as j_resp:
                    j_data = json.loads(j_resp.read().decode())
                    for job in j_data.get("jobs", []):
                        print(f"  Job: {job.get('name')} | Status: {job.get('status')} | Conclusion: {job.get('conclusion')}")
                        for step in job.get("steps", []):
                            if step.get("conclusion") == "failure":
                                print(f"    FAILED STEP: {step.get('name')} (Conclusion: {step.get('conclusion')})")
except Exception as e:
    print("Error:", e)
