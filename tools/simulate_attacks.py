"""
SentinelLog Simulation Tool: Harmless Attack Scenario Generator.
Demonstrates end-to-end detection response for:
1. Encoded PowerShell execution (harmless string print).
2. SQL injection web attack payloads.
3. Rapid authentication brute force bursts.
"""

import argparse
import base64
import subprocess
import time
import requests

API_URL = "http://127.0.0.1:8000"
API_KEY = "sentinel-secret-key-1"


def run_harmless_powershell():
    """Runs a harmless PowerShell command with -EncodedCommand printing 'echo test'."""
    cmd_text = 'echo "SentinelLog Test String"'
    # PowerShell encoded command requires UTF-16LE encoding
    b64_cmd = base64.b64encode(cmd_text.encode("utf-16le")).decode("ascii")
    print(f"[*] Executing harmless encoded PowerShell test...")
    print(f"[*] Command: powershell -NoProfile -EncodedCommand {b64_cmd}")

    try:
        res = subprocess.run(
            ["powershell", "-NoProfile", "-EncodedCommand", b64_cmd],
            capture_output=True,
            text=True,
            timeout=5,
        )
        print(f"[✔] Result output: {res.stdout.strip()}")
    except Exception as e:
        print(f"[!] Subprocess execution note: {e}")


def test_api_sqli_attack():
    """Posts a simulated SQL injection batch to the Ingestion API."""
    print("[*] Posting simulated SQLi attack to API...")
    payload = {
        "events": [
            {
                "ip": "198.51.100.77",
                "method": "GET",
                "url": "/search.php?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users--",
                "raw_url": "/search.php?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users--",
                "decoded_url": "/search.php?id=1' UNION SELECT username,password FROM users--",
                "status": 200,
                "ua": "sqlmap/1.7",
                "rule_ids": ["WEB-SQLI-001"],
                "label": "sqli",
                "url_length": 65,
                "query_length": 55,
                "num_params": 1,
                "special_chars": 12,
                "special_ratio": 0.25,
                "digit_ratio": 0.05,
                "upper_ratio": 0.35,
                "url_entropy": 4.8,
                "has_sql_kw": 1,
                "has_script_tag": 0,
                "has_traversal": 0,
                "has_cmd_kw": 0,
                "method_is_post": 0,
                "is_rare_method": 0,
                "is_404": 0,
            }
        ]
    }

    try:
        r = requests.post(
            f"{API_URL}/ingest/weblog",
            json=payload,
            headers={"X-API-Key": API_KEY},
            timeout=3,
        )
        print(f"[✔] API returned HTTP {r.status_code}: {r.json()}")
    except Exception as e:
        print(f"[!] Could not connect to API at {API_URL}: {e}")


def test_api_brute_force_burst():
    """Simulates an authentication brute force burst."""
    print("[*] Posting simulated brute-force authentication burst...")
    events = []
    for i in range(8):
        events.append({
            "action": "logon_failed",
            "host": "simulated-workstation",
            "actor": f"victim_user_{i}",
            "target": "LocalSystem",
            "rule_hits": [
                {"id": "EP-AUTH-001", "name": "Burst of Failed Windows Logons", "severity": 70}
            ],
            "attrs": {"reason": "Bad password attempt"},
        })

    try:
        r = requests.post(
            f"{API_URL}/ingest/agent",
            json={"events": events},
            headers={"X-API-Key": API_KEY},
            timeout=3,
        )
        print(f"[✔] API returned HTTP {r.status_code}: {r.json()}")
    except Exception as e:
        print(f"[!] Could not connect to API at {API_URL}: {e}")


def main():
    parser = argparse.ArgumentParser(description="SentinelLog Harmless Attack Simulator")
    parser.add_argument("--type", choices=["all", "powershell", "sqli", "brute_force"], default="all")
    args = parser.parse_args()

    if args.type in ("all", "powershell"):
        run_harmless_powershell()
    if args.type in ("all", "sqli"):
        test_api_sqli_attack()
    if args.type in ("all", "brute_force"):
        test_api_brute_force_burst()


if __name__ == "__main__":
    main()
