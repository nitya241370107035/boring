import json
from pathlib import Path


def make_nb(cells):
    return {
        "cells": cells,
        "metadata": {
            "language_info": {"name": "python", "version": "3.11"},
            "kernelspec": {"name": "python3", "display_name": "Python 3"}
        },
        "nbformat": 4,
        "nbformat_minor": 5
    }


def md_cell(source):
    return {
        "cell_type": "markdown",
        "metadata": {},
        "source": source.splitlines(keepends=True) if isinstance(source, str) else source
    }


def code_cell(source):
    return {
        "cell_type": "code",
        "metadata": {},
        "execution_count": None,
        "outputs": [],
        "source": source.splitlines(keepends=True) if isinstance(source, str) else source
    }


def build_all():
    # --- Notebook 01 ---
    nb01_cells = [
        md_cell(
            "# Practical 1: Load and Explore Unstructured Access Log Data\n"
            "**Course:** BE05000231 - PDS (Semester V, GTU GSET)\n"
            "**Course Outcome:** CO1\n\n"
            "### Objective:\n"
            "Load raw, unstructured Apache/Nginx web server access logs safely using memory-efficient generators, "
            "reservoir sampling, and inspect common format tokens."
        ),
        md_cell("## 1. Imports and Setup"),
        code_cell(
            "import sys\n"
            "from pathlib import Path\n"
            "sys.path.append('..')\n\n"
            "from pipeline.ingest import count_lines, detect_format, get_file_summary, sample_lines, stream_lines\n\n"
            "LOG_PATH = Path('../tests/fixtures/sample_access.log')\n"
        ),
        md_cell("## 2. File Metrics and High-Speed Line Count"),
        code_cell(
            "total_lines = count_lines(LOG_PATH)\n"
            "summary = get_file_summary(LOG_PATH)\n"
            "print(f\"File Path: {summary['filepath']}\")\n"
            "print(f\"File Size: {summary['file_size_formatted']}\")\n"
            "print(f\"Total Lines: {summary['total_lines']}\")\n"
            "print(f\"Detected Format: {summary['detected_format']}\")\n"
        ),
        md_cell(
            "## 3. Reservoir Sampling (Memory-Safe Random Inspection)\n"
            "Reservoir sampling allows drawing k representative lines in O(N) time with strictly O(k) memory, "
            "preventing Out-Of-Memory errors on multi-gigabyte log archives."
        ),
        code_cell(
            "samples = sample_lines(LOG_PATH, k=5, seed=42)\n"
            "for idx, sample in enumerate(samples, 1):\n"
            "    print(f'Sample {idx}: {sample}')\n"
        ),
        md_cell("## 4. First and Last Lines Inspection"),
        code_cell(
            "print('--- First 5 Lines ---')\n"
            "for l in summary['first_5_lines']:\n"
            "    print(l)\n\n"
            "print('\\n--- Last 5 Lines ---')\n"
            "for l in summary['last_5_lines']:\n"
            "    print(l)\n"
        ),
        md_cell(
            "## 5. Security Token Value Analysis\n\n"
            "| Token | Example Value | Cyber-Security Value |\n"
            "| :--- | :--- | :--- |\n"
            "| **IP Address** | `198.51.100.7` | Attacker identity, geo-location, burst volumes, reputation |\n"
            "| **Timestamp** | `[10/Oct/2026:13:55:36 +0000]` | Time-of-day profiling, brute-force frequency windows |\n"
            "| **HTTP Method** | `POST` / `GET` | POST to `/login` hints authentication attacks; unusual verbs (`PUT`, `DELETE`, `DEBUG`) |\n"
            "| **URL / Query** | `/products.php?id=1%27+OR+1=1` | Direct injection payloads (SQLi, XSS, path traversal, scans) |\n"
            "| **Status Code** | `404`, `401`, `500` | Scanners trigger 404 clusters; brute-force generates 401; exploit crashes trigger 500 |\n"
            "| **Bytes Sent** | `0` or `500000` | Outliers indicate data exfiltration or blocked requests |\n"
            "| **User-Agent** | `sqlmap/1.7`, `Nikto` | Automated penetration tools vs real browser signatures |\n\n"
            "### Conclusion:\n"
            "Practical 1 successfully established safe ingestion primitives and parsed critical structural tokens from unstructured server access logs."
        ),
    ]

    with open("notebooks/01_load_explore.ipynb", "w", encoding="utf-8") as f:
        json.dump(make_nb(nb01_cells), f, indent=2)

    # --- Notebook 02 ---
    nb02_cells = [
        md_cell(
            "# Practical 2: Convert Unstructured Log Data into a Structured Dataset\n"
            "**Course:** BE05000231 - PDS (Semester V, GTU GSET)\n"
            "**Course Outcome:** CO1\n\n"
            "### Objective:\n"
            "Convert unstructured text logs into a structured Pandas DataFrame via compiled regular expressions, "
            "handle edge cases (IPv6, dash bytes, missing fields), log unparseable rejects, and serialize to Apache Parquet."
        ),
        md_cell("## 1. Imports and Setup"),
        code_cell(
            "import sys\n"
            "from pathlib import Path\n"
            "sys.path.append('..')\n"
            "import pandas as pd\n\n"
            "from pipeline.parser import parse_file, parse_report\n\n"
            "LOG_PATH = Path('../tests/fixtures/sample_access.log')\n"
            "REJECTS_PATH = Path('../data/interim/rejects.txt')\n"
            "PARQUET_PATH = Path('../data/processed/structured_logs.parquet')\n"
        ),
        md_cell("## 2. Execute Structured Parsing"),
        code_cell(
            "df, rejects = parse_file(\n"
            "    LOG_PATH,\n"
            "    chunk_size=1000,\n"
            "    rejects_path=REJECTS_PATH,\n"
            "    output_parquet=PARQUET_PATH\n"
            ")\n\n"
            "print(f'Successfully parsed rows: {len(df)}')\n"
            "print(f'Rejected malformed lines: {len(rejects)}')\n"
        ),
        md_cell("## 3. Parse Quality & Audit Report"),
        code_cell(
            "report = parse_report(total_attempted=len(df) + len(rejects), parsed_count=len(df), rejected_count=len(rejects))\n"
            "for k, v in report.items():\n"
            "    print(f'{k}: {v}')\n"
        ),
        md_cell("## 4. Inspection of Structured DataFrame Schema and Types"),
        code_cell(
            "print(df.info())\n"
            "df.head(8)\n"
        ),
        md_cell(
            "## 5. Audit Rejected Lines\n"
            "Attack traffic often contains corrupted or non-standard bytes. Segregating rejects prevents pipeline crashes while retaining evidence."
        ),
        code_cell(
            "print('--- Rejected Malformed Lines ---')\n"
            "for line_no, raw in rejects:\n"
            "    print(f'Line {line_no}: {raw}')\n"
        ),
        md_cell("## 6. Parquet Verification"),
        code_cell(
            "loaded_parquet = pd.read_parquet(PARQUET_PATH)\n"
            "print(f'Parquet verified. Row count: {len(loaded_parquet)}, Columns: {list(loaded_parquet.columns)}')\n"
        ),
        md_cell(
            "### Conclusion:\n"
            "Practical 2 demonstrated robust parsing of unstructured log data into a typed, memory-efficient Pandas DataFrame and Parquet storage, retaining audit traces of rejected lines."
        ),
    ]

    with open("notebooks/02_structured_dataset.ipynb", "w", encoding="utf-8") as f:
        json.dump(make_nb(nb02_cells), f, indent=2)

    # --- Notebook 03 ---
    nb03_cells = [
        md_cell(
            "# Practical 3: Clean the Data and Preprocess\n"
            "**Course:** BE05000231 - PDS (Semester V, GTU GSET)\n"
            "**Course Outcome:** CO2\n\n"
            "### Objective:\n"
            "Clean and preprocess structured log data: apply multi-pass URL decoding to expose evasion techniques, "
            "normalize paths without erasing attack traces, standardize missing fields, and generate data quality metrics."
        ),
        md_cell("## 1. Imports and Setup"),
        code_cell(
            "import sys\n"
            "from pathlib import Path\n"
            "sys.path.append('..')\n"
            "import pandas as pd\n\n"
            "from pipeline.parser import parse_file\n"
            "from pipeline.cleaner import clean, deep_decode, normalize_path, data_quality_report\n\n"
            "LOG_PATH = Path('../tests/fixtures/sample_access.log')\n"
        ),
        md_cell(
            "## 2. Deep URL Decoding Demonstration\n"
            "Attackers often utilize double or triple URL-encoding (e.g. `%2527` -> `%27` -> `'`) to bypass single-pass web application firewalls."
        ),
        code_cell(
            "sample_evasion = 'cat%2527s%20OR%201%3D1--'\n"
            "print('Raw Payload:          ', sample_evasion)\n"
            "print('Single unquote:       ', deep_decode(sample_evasion, max_iter=1))\n"
            "print('Deep decode (iter=3): ', deep_decode(sample_evasion, max_iter=3))\n"
        ),
        md_cell(
            "## 3. Path Normalization vs Attack Preservation\n"
            "Path normalization collapses consecutive slashes and standardizes root aliases (`/index.html` -> `/`). "
            "However, raw and decoded URLs MUST be retained so traversal attacks (`../`) remain detectable."
        ),
        code_cell(
            "print('Normalized //api///v1/ :', normalize_path('//api///v1/'))\n"
            "print('Normalized /INDEX.HTML  :', normalize_path('/INDEX.HTML'))\n"
        ),
        md_cell("## 4. Run Cleaning Pipeline"),
        code_cell(
            "raw_df, _ = parse_file(LOG_PATH)\n"
            "cleaned_df = clean(raw_df)\n\n"
            "print(f'Cleaned DataFrame Rows: {len(cleaned_df)}')\n"
            "cleaned_df[['ip', 'method', 'path', 'query', 'decoded_url', 'ua']].head(10)\n"
        ),
        md_cell("## 5. Comprehensive Data Quality Audit"),
        code_cell(
            "report = data_quality_report(cleaned_df)\n"
            "for k, v in report.items():\n"
            "    print(f'{k}: {v}')\n"
        ),
        md_cell(
            "### Conclusion:\n"
            "Practical 3 successfully resolved missing values, established timezone-aware chronological ordering, "
            "exposed obfuscated payloads via deep decoding, and generated comprehensive data quality reports."
        ),
    ]

    with open("notebooks/03_clean_preprocess.ipynb", "w", encoding="utf-8") as f:
        json.dump(make_nb(nb03_cells), f, indent=2)

    print("All 3 notebooks built successfully.")


if __name__ == "__main__":
    build_all()
