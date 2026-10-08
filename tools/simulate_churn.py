"""
SentinelLog Simulation Tool: Safe File Churn Generator.
Simulates high-frequency file modifications (ransomware simulation) in a temporary folder
to trigger and validate agent/collectors/files.py without impacting user files.
"""

import argparse
from pathlib import Path
import time


def simulate_churn(target_dir: str | Path, count: int = 100, delay_ms: float = 10.0):
    folder = Path(target_dir)
    folder.mkdir(parents=True, exist_ok=True)
    print(f"[*] Starting safe file churn simulation in: {folder.resolve()}")
    print(f"[*] Target count: {count} files | Delay: {delay_ms} ms")

    created_files = []
    # 1. Batch Create
    for i in range(count):
        file_path = folder / f"test_doc_{i:04d}.tmp"
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(f"Sample test content line for file {i}\n")
        created_files.append(file_path)
        if delay_ms > 0:
            time.sleep(delay_ms / 1000.0)

    print(f"[+] Created {len(created_files)} files. Now simulating rapid ransomware renaming...")

    # 2. Rapid Rename
    renamed_files = []
    for fp in created_files:
        new_path = fp.with_suffix(".locked")
        fp.rename(new_path)
        renamed_files.append(new_path)
        if delay_ms > 0:
            time.sleep(delay_ms / 1000.0)

    print(f"[+] Renamed {len(renamed_files)} files to .locked extension!")
    print("[*] Sleeping 5 seconds to allow file observer window evaluation...")
    time.sleep(5)

    # 3. Clean Up
    print("[*] Cleaning up temporary simulation files...")
    for fp in renamed_files:
        try:
            fp.unlink()
        except Exception:
            pass

    print("[✔] Safe churn simulation completed cleanly.")


def main():
    parser = argparse.ArgumentParser(description="SentinelLog Safe File Churn Simulator")
    parser.add_argument("--path", default="tests/fixtures/churn_test", help="Target test folder")
    parser.add_argument("--count", type=int, default=80, help="Number of files to churn")
    parser.add_argument("--delay", type=float, default=5.0, help="Delay between operations in ms")
    args = parser.parse_args()

    simulate_churn(args.path, count=args.count, delay_ms=args.delay)


if __name__ == "__main__":
    main()
