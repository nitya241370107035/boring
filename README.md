# SentinelLog

> **Real-World Log Analysis and Endpoint Threat Detection Platform**  
> Course: *BE05000231 – Predictive Data Science (PDS), Semester V*  
> Gujarat Technological University – GSET, AY 2026-27 ODD

---

## Overview
SentinelLog is an enterprise-grade hybrid security analytics platform uniting two core data streams:
1. **Web Server Access Logs**: Real-world Apache and Nginx access logs analyzed through a modular 10-stage data science pipeline (Practicals 1–10).
2. **Windows Endpoint Telemetry**: A lightweight host agent monitoring processes, network connections, Windows Security events (4624, 4625, 4688), file modification churn (ransomware detection), and persistence mechanisms.

---

## Key Features
- **Explainable Multi-Tier Detection**: Rule signatures (YAML), statistical baselines (novelty tracking), and ML classifiers (Random Forest, XGBoost, Isolation Forest) combined into a calibrated severity score (0–100).
- **GTU Syllabus Aligned**: 10 clean Jupyter notebooks in `notebooks/` corresponding 1:1 with production modules in `pipeline/` and `models/`.
- **Production Architecture**: FastAPI ingestion server, SQLite / PostgreSQL persistence, and interactive Streamlit dashboard.
- **Fail-Safe Endpoint Agent**: SQLite local offline buffering with batch retries, secrets redaction, and bounded CPU/RAM footprint.

---

## Repository Structure
```text
sentinellog/
├── agent/                  # Windows endpoint collector & local engine
│   ├── collectors/         # processes, network, eventlog, files, persistence
│   ├── main.py, rules.py, sender.py, config.yaml
├── pipeline/               # Core data science pipeline (Practicals 1–5, 7, 10)
│   ├── ingest.py, parser.py, cleaner.py, labeler.py, features.py, wrangle.py, run.py
├── models/                 # Model training, balancing & evaluation (Practicals 6, 9)
│   ├── balance.py, train.py, evaluate.py, explain.py, artifacts/
├── api/                    # Central FastAPI ingestion & scoring service
│   ├── main.py, schemas.py, db.py, auth.py, scoring.py
├── dashboard/              # Streamlit multi-page monitoring dashboard
│   ├── app.py, pages/
├── rules/                  # Detection rules and allowlists
│   ├── web_rules.yaml, endpoint_rules.yaml, allowlist.yaml
├── notebooks/              # Practical lab submissions (01 to 10)
├── tests/                  # Unit and integration test suite
│   ├── fixtures/sample_access.log
├── tools/                  # Harmless attack simulators
├── docker/                 # Containerization artifacts
└── requirements.txt, pyproject.toml, .env.example
```

---

## GTU Practical Mapping
| Practical | Topic | Module | Notebook |
| :---: | :--- | :--- | :--- |
| **01** | Load and explore unstructured access log data | `pipeline/ingest.py` | `notebooks/01_load_explore.ipynb` |
| **02** | Convert unstructured logs to structured dataset | `pipeline/parser.py` | `notebooks/02_structured_dataset.ipynb` |
| **03** | Clean the data and preprocess | `pipeline/cleaner.py` | `notebooks/03_clean_preprocess.ipynb` |
| **04** | Label requests as benign or attack | `pipeline/labeler.py` | `notebooks/04_labeling.ipynb` |
| **05** | Feature engineering for anomaly detection | `pipeline/features.py` | `notebooks/05_feature_engineering.ipynb` |
| **06** | Balance the dataset for ML/DL training | `models/balance.py` | `notebooks/06_balance.ipynb` |
| **07** | Data wrangling for aggregated analysis | `pipeline/wrangle.py` | `notebooks/07_wrangle.ipynb` |
| **08** | Data visualization and exploratory data analysis | `dashboard/pages/eda.py` | `notebooks/08_eda.ipynb` |
| **09** | Build classifier to detect attacks | `models/train.py` | `notebooks/09_classifier.ipynb` |
| **10** | Create a reusable data pipeline | `pipeline/run.py` | `notebooks/10_reusable_pipeline.ipynb` |

---

## Quickstart

### 1. Environment Setup
```powershell
# Create & activate virtual environment
python -m venv .venv
.venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Run Tests
```powershell
pytest
```

### 3. Run Pipeline CLI
```powershell
python -m pipeline.run tests/fixtures/sample_access.log --out data/processed/sample.parquet
```

### 4. Launch Server & Dashboard
```powershell
# In terminal 1: Start API server
uvicorn api.main:app --reload --port 8000

# In terminal 2: Start Streamlit dashboard
streamlit run dashboard/app.py
```

### 5. Dockerized Deployment
```bash
# Production multi-container stack (PostgreSQL + FastAPI + Streamlit)
docker compose up --build

# Optional DVWA Honeynet Lab
docker compose -f docker-compose.lab.yml up -d
```

### 6. Simulation & Live Testing Tools
```powershell
# Safe file churn simulation (ransomware test)
python tools/simulate_churn.py --count 50

# Harmless attacks against live API (SQLi, PowerShell, Brute Force)
python tools/simulate_attacks.py --powershell --sqli --brute
```

---

## Academic Defense & Viva Preparation
For thorough answers to all theoretical and implementation defense questions, refer to:
📖 **[Comprehensive Viva Preparation Guide](file:///d:/pds_final/docs/viva_preparation.md)**
- Precision/Recall vs Accuracy under severe cyber imbalance
- Zero data leakage SMOTE partitioning
- Shannon entropy mathematical foundation
- Sliding-window temporal attack detection mechanics
- Endpoint collector safety and <2% CPU throttling
- Multi-signal hybrid threat scoring formula

