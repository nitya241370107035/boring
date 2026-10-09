"""
SentinelLog Pipeline: Log Analyzer & Ingestion Engine.
Processes arbitrary real-world access log files (Apache, Nginx, JSON Lines, CSV).
Executes end-to-end parsing, feature extraction, ML classification, threat scoring,
statistical aggregations, and optional live SIEM database ingestion.
"""

from datetime import datetime, timezone
import io
import json
import logging
import re
import time
from typing import Any
import uuid

import numpy as np
import pandas as pd
from sqlalchemy.orm import Session

from api.scoring import AlertSuppressionEngine, calculate_severity
from models.evaluate import predict_event
from pipeline import cleaner, features, labeler
from pipeline.cleaner import deep_decode

logger = logging.getLogger("sentinellog.analyzer")

# Regex supporting Apache & Nginx combined/common logs
LOG_COMBINED_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<url>\S+)(?:\s+(?P<proto>[^"]*))?"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\S+)'
    r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<ua>[^"]*)")?.*$'
)

# Tolerant fallback regex for looser log patterns
LOG_LOOSE_RE = re.compile(
    r'(?P<ip>\b(?:\d{1,3}\.){3}\d{1,3}\b|[a-fA-F0-9:]{3,})\s+.*?'
    r'"(?P<method>[A-Z]{3,7})\s+(?P<url>\S+)(?:\s+[A-Z0-9./]+)?"\s+'
    r'(?P<status>\d{3})(?:\s+(?P<bytes>\S+))?'
)


def parse_single_line(line: str) -> dict[str, Any] | None:
    """Parses a single line in Combined, Common, JSON, or fallback format."""
    s = line.strip()
    if not s or s.startswith("#"):
        return None

    # 1. JSON Lines
    if s.startswith("{") and s.endswith("}"):
        try:
            d = json.loads(s)
            url = d.get("url") or d.get("uri") or d.get("path") or "/"
            return {
                "ip": str(d.get("ip") or d.get("client_ip") or "127.0.0.1"),
                "user": str(d.get("user") or "-"),
                "ts": str(d.get("ts") or d.get("timestamp") or datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")),
                "method": str(d.get("method") or "GET").upper(),
                "url": url,
                "proto": str(d.get("proto") or "HTTP/1.1"),
                "status": int(d.get("status") or 200),
                "bytes": str(d.get("bytes") or "0"),
                "referrer": str(d.get("referrer") or "-"),
                "ua": str(d.get("ua") or d.get("user_agent") or "Mozilla/5.0"),
            }
        except Exception:
            pass

    # 2. Apache / Nginx Combined Regex
    m = LOG_COMBINED_RE.match(s)
    if m:
        res = m.groupdict()
        res.setdefault("referrer", "-")
        res.setdefault("ua", "-")
        res["status"] = int(res["status"])
        return res

    # 3. Loose regex fallback
    m_loose = LOG_LOOSE_RE.search(s)
    if m_loose:
        res = m_loose.groupdict()
        res.setdefault("user", "-")
        res.setdefault("ts", datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000"))
        res.setdefault("proto", "HTTP/1.1")
        res.setdefault("referrer", "-")
        res.setdefault("ua", "-")
        res["status"] = int(res["status"])
        res["bytes"] = res.get("bytes") or "0"
        return res

    return None


def parse_csv_content(content: str) -> list[dict[str, Any]]:
    """Attempts CSV parsing if standard headers are present."""
    try:
        df_csv = pd.read_csv(io.StringIO(content))
        cols_lower = [c.lower().strip() for c in df_csv.columns]
        mapping = dict(zip(cols_lower, df_csv.columns))
        if "url" in cols_lower or "path" in cols_lower or "uri" in cols_lower:
            url_col = mapping.get("url") or mapping.get("path") or mapping.get("uri")
            ip_col = mapping.get("ip") or mapping.get("client_ip") or mapping.get("remote_addr")
            method_col = mapping.get("method") or mapping.get("verb")
            status_col = mapping.get("status") or mapping.get("status_code")
            ua_col = mapping.get("ua") or mapping.get("user_agent")
            ts_col = mapping.get("ts") or mapping.get("timestamp") or mapping.get("time")

            rows = []
            for _, r in df_csv.iterrows():
                rows.append({
                    "ip": str(r[ip_col]) if ip_col and pd.notna(r.get(ip_col)) else "127.0.0.1",
                    "user": "-",
                    "ts": str(r[ts_col]) if ts_col and pd.notna(r.get(ts_col)) else datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000"),
                    "method": str(r[method_col]).upper() if method_col and pd.notna(r.get(method_col)) else "GET",
                    "url": str(r[url_col]) if pd.notna(r.get(url_col)) else "/",
                    "proto": "HTTP/1.1",
                    "status": int(r[status_col]) if status_col and pd.notna(r.get(status_col)) else 200,
                    "bytes": "0",
                    "referrer": "-",
                    "ua": str(r[ua_col]) if ua_col and pd.notna(r.get(ua_col)) else "Mozilla/5.0",
                })
            return rows
    except Exception:
        pass
    return []


def analyze_log_content(
    content: str,
    filename: str = "uploaded_log.log",
    ingest_to_db: bool = False,
    db: Session | None = None,
    rules_path: str = "rules/web_rules.yaml",
) -> dict[str, Any]:
    """
    Analyzes raw log content string, extracts features, performs ML inference,
    computes rich summary statistics, and optionally persists events and alerts.
    """
    t0 = time.time()
    raw_lines = content.splitlines()
    total_lines = len(raw_lines)

    parsed_rows: list[dict[str, Any]] = []
    reject_count = 0

    # Test if entire file is CSV
    if total_lines > 1 and ("," in raw_lines[0] or "\t" in raw_lines[0]):
        csv_rows = parse_csv_content(content)
        if csv_rows:
            parsed_rows = csv_rows
            detected_format = "CSV Delimited Web Log"

    if not parsed_rows:
        detected_format = "Apache/Nginx Combined"
        for line in raw_lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            row = parse_single_line(stripped)
            if row:
                parsed_rows.append(row)
            else:
                reject_count += 1

    if not parsed_rows:
        return {
            "status": "error",
            "message": "No valid log lines could be parsed from the provided content.",
            "total_lines": total_lines,
            "parsed_rows": 0,
            "reject_count": reject_count,
        }

    # Format detection refinement
    if detected_format != "CSV Delimited Web Log":
        if any(r.get("ua") and r["ua"] != "-" for r in parsed_rows[:10]):
            detected_format = "Apache/Nginx Combined Log"
        else:
            detected_format = "Apache Common Access Log"

    # Convert to DataFrame and preprocess using parser finalizer
    from pipeline.parser import _finalize_dataframe
    raw_df = _finalize_dataframe(parsed_rows)
    clean_df = cleaner.clean(raw_df)

    # Apply Rule Signatures
    rules = labeler.load_rules(rules_path)
    labeled_df = labeler.label_requests(clean_df, rules)

    # Feature Engineering
    req_feat = features.add_request_features(labeled_df)

    # ML Inference (Random Forest + Isolation Forest)
    probs, anomalies = predict_event(req_feat)

    # Calculate calibrated severity and assemble event records
    processed_events: list[dict[str, Any]] = []
    attacks_count = 0
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "BENIGN": 0}
    attack_cat_counts: dict[str, int] = {}
    status_counts: dict[str, int] = {}
    methods_counts: dict[str, int] = {}
    attacker_ip_map: dict[str, dict[str, Any]] = {}
    targeted_path_map: dict[str, dict[str, Any]] = {}

    suppression_engine = AlertSuppressionEngine(suppression_window_seconds=600.0)
    alerts_created = 0
    events_ingested = 0

    for idx, row in req_feat.iterrows():
        ml_p = float(probs[idx])
        ano_s = float(anomalies[idx])
        rule_ids = list(row.get("rule_ids", []))
        rule_hits = [{"id": rid, "name": f"Rule {rid}", "severity": 85} for rid in rule_ids]

        score, sev_level, reasons = calculate_severity(
            rule_hits=rule_hits,
            ml_prob=ml_p,
            anomaly=ano_s,
            baseline_novelty=False,
        )

        label = str(row.get("label", "benign"))
        is_attack = label != "benign" or score >= 60

        if is_attack:
            attacks_count += 1
            attack_cat = label if label != "benign" else "anomaly"
            attack_cat_counts[attack_cat] = attack_cat_counts.get(attack_cat, 0) + 1

        # Severity grouping
        if score >= 80:
            sev_group = "CRITICAL"
        elif score >= 60:
            sev_group = "HIGH"
        elif score >= 40:
            sev_group = "MEDIUM"
        elif score >= 20:
            sev_group = "LOW"
        else:
            sev_group = "BENIGN"
        severity_counts[sev_group] += 1

        # Status & Method distribution
        st_code = str(row.get("status", 200))
        status_counts[st_code] = status_counts.get(st_code, 0) + 1
        meth = str(row.get("method", "GET"))
        methods_counts[meth] = methods_counts.get(meth, 0) + 1

        # IP Aggregations
        ip = str(row.get("ip", "unknown"))
        if ip not in attacker_ip_map:
            attacker_ip_map[ip] = {
                "ip": ip,
                "total_requests": 0,
                "attack_count": 0,
                "max_score": 0.0,
                "highest_severity": "BENIGN",
                "attack_types": set(),
            }
        ip_entry = attacker_ip_map[ip]
        ip_entry["total_requests"] += 1
        if is_attack:
            ip_entry["attack_count"] += 1
            ip_entry["attack_types"].add(label)
        if score > ip_entry["max_score"]:
            ip_entry["max_score"] = round(score, 1)
            ip_entry["highest_severity"] = sev_level

        # Target Path Aggregations
        path = str(row.get("path") or row.get("url") or "/")
        clean_path = path.split("?")[0]
        if clean_path not in targeted_path_map:
            targeted_path_map[clean_path] = {
                "path": clean_path,
                "hits": 0,
                "attacks": 0,
                "attack_types": set(),
            }
        p_entry = targeted_path_map[clean_path]
        p_entry["hits"] += 1
        if is_attack:
            p_entry["attacks"] += 1
            p_entry["attack_types"].add(label)

        # Assemble row record
        rec = {
            "id": idx + 1,
            "ts": str(row.get("ts", "")),
            "ip": ip,
            "method": meth,
            "url": str(row.get("url", "")),
            "decoded_url": str(row.get("decoded_url", row.get("url", ""))),
            "status": int(row.get("status", 200)),
            "bytes": str(row.get("bytes", "0")),
            "ua": str(row.get("ua", "-")),
            "label": label,
            "score": round(score, 1),
            "severity": sev_level,
            "reasons": reasons,
            "rule_ids": rule_ids,
            "ml_probability": round(ml_p, 4),
            "anomaly_score": round(ano_s, 4),
            "features": {
                "url_length": int(row.get("url_length", len(str(row.get("url", ""))))),
                "url_entropy": round(float(row.get("url_entropy", 0.0)), 3),
                "special_chars": int(row.get("special_chars", 0)),
                "has_sql_kw": int(row.get("has_sql_kw", 0)),
                "has_script_tag": int(row.get("has_script_tag", 0)),
                "has_traversal": int(row.get("has_traversal", 0)),
            },
        }
        processed_events.append(rec)

        # Optional database ingestion into live SOC platform
        if ingest_to_db and db is not None:
            from api.db import AlertModel, EventModel

            evt_id = f"upload-{uuid.uuid4().hex[:10]}"
            db_event = EventModel(
                event_id=evt_id,
                source="weblog_upload",
                host="uploaded-server",
                actor=ip,
                action=f"{meth} {clean_path}",
                target=str(row.get("url", "")),
                attrs_json=json.dumps({"status": row.get("status"), "ua": row.get("ua"), "filename": filename}),
                label=label,
                score=score,
                reasons_json=json.dumps(reasons),
            )
            db.add(db_event)
            events_ingested += 1

            if score >= 60 and rule_hits:
                top_rule = rule_hits[0]["id"]
                is_suppressed, alert_id, count = suppression_engine.process_alert(
                    host="uploaded-server",
                    rule_id=top_rule,
                    target=ip,
                )
                if not is_suppressed:
                    new_alert = AlertModel(
                        alert_id=alert_id,
                        host="uploaded-server",
                        rule_id=top_rule,
                        severity=sev_level,
                        score=score,
                        status="open",
                        reasons_json=json.dumps(reasons),
                        evidence_json=json.dumps(rec),
                        count=1,
                    )
                    db.add(new_alert)
                    alerts_created += 1

    if ingest_to_db and db is not None:
        db.commit()

    # Format Top IPs list
    top_ips = sorted(
        attacker_ip_map.values(),
        key=lambda x: (x["attack_count"], x["max_score"]),
        reverse=True,
    )[:12]
    for item in top_ips:
        item["attack_types"] = sorted(list(item["attack_types"]))

    # Format Top Paths list
    top_paths = sorted(
        targeted_path_map.values(),
        key=lambda x: (x["attacks"], x["hits"]),
        reverse=True,
    )[:10]
    for item in top_paths:
        item["attack_types"] = sorted(list(item["attack_types"]))

    # Sort events by score desc for priority viewing
    events_preview = sorted(processed_events, key=lambda x: x["score"], reverse=True)[:250]

    elapsed = round(time.time() - t0, 3)
    throughput = round(len(parsed_rows) / max(elapsed, 0.001), 1)

    return {
        "status": "success",
        "filename": filename,
        "elapsed_seconds": elapsed,
        "throughput_lines_sec": throughput,
        "total_lines": total_lines,
        "parsed_rows": len(parsed_rows),
        "rejected_lines": reject_count,
        "success_rate_percent": round((len(parsed_rows) / max(total_lines, 1)) * 100, 1),
        "detected_format": detected_format,
        "total_attacks": attacks_count,
        "attack_rate_percent": round((attacks_count / max(len(parsed_rows), 1)) * 100, 1),
        "severity_distribution": severity_counts,
        "threat_categories": attack_cat_counts,
        "status_distribution": status_counts,
        "method_distribution": methods_counts,
        "top_ips": top_ips,
        "top_paths": top_paths,
        "events": events_preview,
        "ingest_to_db": ingest_to_db,
        "events_ingested": events_ingested,
        "alerts_created": alerts_created,
    }


def generate_markdown_report(data: dict[str, Any]) -> str:
    """Generates an executive-grade Markdown SOC Incident and Security Audit Report."""
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    report_id = f"SOC-AUDIT-{uuid.uuid4().hex[:8].upper()}"
    filename = data.get("filename", "uploaded_log.log")
    total_lines = data.get("total_lines", 0)
    parsed_rows = data.get("parsed_rows", 0)
    total_attacks = data.get("total_attacks", 0)
    attack_rate = data.get("attack_rate_percent", 0.0)
    fmt = data.get("detected_format", "Web Access Log")
    sev_dist = data.get("severity_distribution", {})
    categories = data.get("threat_categories", {})
    top_ips = data.get("top_ips", [])
    top_paths = data.get("top_paths", [])
    events = data.get("events", [])

    peak_score = max((e.get("score", 0) for e in events), default=0)
    overall_sev = (
        "CRITICAL" if peak_score >= 80 else
        "HIGH" if peak_score >= 60 else
        "MEDIUM" if peak_score >= 40 else
        "LOW" if peak_score >= 20 else
        "BENIGN / INFORMATIONAL"
    )

    mitre_map = {
        "sqli": ("T1190", "Exploit Public-Facing Application: SQL Injection"),
        "xss": ("T1059.007", "Command and Scripting: JavaScript / Cross-Site Scripting"),
        "traversal": ("T1083", "File and Directory Discovery: Directory Traversal"),
        "path_traversal": ("T1083", "File and Directory Discovery: Directory Traversal"),
        "cmdi": ("T1059.004", "Command and Scripting: Unix/Windows Shell Execution"),
        "scan": ("T1595.002", "Active Scanning: Vulnerability & Path Fuzzing"),
        "brute": ("T1110.001", "Brute Force: Password Guessing / Credential Burst"),
        "brute_force": ("T1110.001", "Brute Force: Password Guessing / Credential Burst"),
        "anomaly": ("T1204", "User Execution: Out-of-Distribution Anomalous Request"),
    }

    lines = [
        f"# 🛡️ SentinelLog Incident & Access Log Security Audit Report",
        f"> **Document Ref:** `{report_id}`  ",
        f"> **Classification:** `CONFIDENTIAL // TLP:AMBER // SOC INTERNAL USE`  ",
        f"> **Generated:** `{now_str}`  ",
        f"> **Telemetry Source:** `{filename}` ({fmt})  ",
        f"",
        f"---",
        f"",
        f"## 1. Executive Summary",
        f"SentinelLog hybrid threat detection engine analyzed **{total_lines:,}** log telemetry lines from source `{filename}`. The analysis identified **{total_attacks}** malicious exploit attempts (**{attack_rate}%** threat ratio) with an overall platform risk verdict of **{overall_sev}** (Peak Threat Score: **{peak_score:.1f}/100**).",
        f"",
        f"| Metric | Assessment Result | Operational Significance |",
        f"| :--- | :--- | :--- |",
        f"| **Log File Analyzed** | `{filename}` | Source telemetry audited |",
        f"| **Detected Format** | `{fmt}` | Heuristic format parser |",
        f"| **Total Processed Rows** | **{parsed_rows:,}** ({data.get('success_rate_percent', 100)}% valid) | Parsing success rate |",
        f"| **Threat Volume** | **{total_attacks} attacks** | Malicious requests identified |",
        f"| **Threat Density** | **{attack_rate}%** | Percentage of malicious requests |",
        f"| **Peak Threat Score** | **{peak_score:.1f} / 100** | Calibrated composite risk score |",
        f"| **Overall Risk Verdict** | **{overall_sev}** | Tier 1 SOC escalation recommendation |",
        f"| **Processing Speed** | **{data.get('throughput_lines_sec', 0):,} lines/sec** | Engine throughput ({data.get('elapsed_seconds', 0)}s) |",
        f"",
        f"### Severity Classification Breakdown",
        f"- **CRITICAL (≥80):** {sev_dist.get('CRITICAL', 0)} events",
        f"- **HIGH (60–79):** {sev_dist.get('HIGH', 0)} events",
        f"- **MEDIUM (40–59):** {sev_dist.get('MEDIUM', 0)} events",
        f"- **LOW (20–39):** {sev_dist.get('LOW', 0)} events",
        f"- **BENIGN (<20):** {sev_dist.get('BENIGN', 0)} events",
        f"",
        f"---",
        f"",
        f"## 2. Threat Vector Breakdown & MITRE ATT&CK Mapping",
        f"",
        f"| Threat Vector | Hits | MITRE ID | Technique Description |",
        f"| :--- | :--- | :--- | :--- |",
    ]

    for cat_name, hit_count in sorted(categories.items(), key=lambda x: x[1], reverse=True):
        m_id, m_desc = mitre_map.get(cat_name, ("T1000", "Generic Web Exploitation"))
        lines.append(f"| **{cat_name.upper()}** | `{hit_count}` | `{m_id}` | {m_desc} |")

    if not categories:
        lines.append("| *None* | `0` | `-` | No malicious exploit signatures matched |")

    lines.extend([
        f"",
        f"---",
        f"",
        f"## 3. Key Indicators of Compromise (Attacker IPs)",
        f"",
        f"| Client IP | Total Requests | Malicious Hits | Max Score | Severity | Detected Vector Types |",
        f"| :--- | :--- | :--- | :--- | :--- | :--- |",
    ])

    for ip_info in top_ips[:10]:
        v_tags = ", ".join(ip_info.get("attack_types", [])) or "benign"
        lines.append(
            f"| `{ip_info['ip']}` | {ip_info['total_requests']} | **{ip_info['attack_count']}** | "
            f"`{ip_info['max_score']}` | **{ip_info['highest_severity']}** | `{v_tags}` |"
        )

    lines.extend([
        f"",
        f"---",
        f"",
        f"## 4. Targeted Vulnerable Endpoints",
        f"",
        f"| Target Path / Endpoint | Total Hits | Attack Exploits | Detected Attack Types |",
        f"| :--- | :--- | :--- | :--- |",
    ])

    for p_info in top_paths[:8]:
        v_tags = ", ".join(p_info.get("attack_types", [])) or "benign"
        lines.append(f"| `{p_info['path']}` | {p_info['hits']} | **{p_info['attacks']}** | `{v_tags}` |")

    lines.extend([
        f"",
        f"---",
        f"",
        f"## 5. Forensic Evidence Samples (Top Incidents)",
        f"",
        f"| # | Timestamp | Source IP | Method | Target URL / Payload | Status | Score | Verdict |",
        f"| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ])

    for ev in events[:15]:
        trunc_url = ev["url"][:60] + ("…" if len(ev["url"]) > 60 else "")
        lines.append(
            f"| {ev['id']} | `{ev['ts']}` | `{ev['ip']}` | **{ev['method']}** | "
            f"`{trunc_url}` | `{ev['status']}` | `{ev['score']}` | **{ev['severity']}** |"
        )

    lines.extend([
        f"",
        f"---",
        f"",
        f"## 6. Recommended SOC Remediation & Hardening Actions",
        f"",
        f"### A. Immediate Containment (Firewall / Reverse Proxy)",
        f"Block malicious attacker IPs observed conducting high-severity attacks:",
        f"```bash",
    ])

    for ip_info in top_ips[:5]:
        if ip_info["attack_count"] > 0:
            lines.append(f"iptables -A INPUT -s {ip_info['ip']} -j DROP  # {ip_info['highest_severity']} ({', '.join(ip_info['attack_types'])})")

    lines.extend([
        f"```",
        f"",
        f"### B. Web Application Hardening",
        f"1. **SQL Injection Mitigation:** Implement Parameterized Queries (Prepared Statements / ORM) across all endpoints with dynamic query parameters.",
        f"2. **XSS Prevention:** Enforce context-sensitive output encoding and configure Content-Security-Policy (`CSP: default-src 'self'`).",
        f"3. **Directory Traversal:** Whitelist acceptable file downloads using strict basename sanitization and eliminate dynamic file inclusion parameters.",
        f"4. **Reconnaissance & Brute Force:** Deploy IP rate limiting at the reverse proxy (e.g. Nginx `limit_req_zone`) for authentication routes (`/login`, `/auth`, `/wp-login.php`).",
        f"",
        f"---",
        f"",
        f"## 7. Sign-off & Audit Verification",
        f"- **Audit Verification:** Automated Machine Learning Pipeline & Explainable Rule Engine",
        f"- **Platform Version:** SentinelLog v1.0 (BE05000231 Practical Data Science)",
        f"- **Analyst Signature:** `SOC-AI-ANALYST-{report_id}`",
        f"- **Status:** Certified Incident Audit Completed",
    ])

    return "\n".join(lines)

