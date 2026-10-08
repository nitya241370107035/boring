"""
SentinelLog Data Pipeline Module.
Implements the core data science workflows for GTU PDS Practicals 1-5, 7, and 10.
"""

from pipeline.ingest import count_lines, detect_format, get_file_summary, sample_lines, stream_lines
from pipeline.parser import parse_file, parse_line, parse_report
from pipeline.cleaner import clean, deep_decode, normalize_path, data_quality_report
from pipeline.labeler import evaluate_labeling, ground_truth_label, label_requests, load_rules
from pipeline.features import (
    add_request_features,
    add_window_features,
    classify_ua,
    generate_feature_catalogue,
    shannon_entropy,
)
from pipeline.wrangle import (
    create_pivots,
    enrich_geoip,
    filter_noise,
    ip_summary,
    is_internal,
    resample_traffic,
)

__all__ = [
    "stream_lines",
    "sample_lines",
    "count_lines",
    "detect_format",
    "get_file_summary",
    "parse_line",
    "parse_file",
    "parse_report",
    "deep_decode",
    "normalize_path",
    "clean",
    "data_quality_report",
    "load_rules",
    "label_requests",
    "ground_truth_label",
    "evaluate_labeling",
    "shannon_entropy",
    "classify_ua",
    "add_request_features",
    "add_window_features",
    "generate_feature_catalogue",
    "is_internal",
    "filter_noise",
    "ip_summary",
    "resample_traffic",
    "create_pivots",
    "enrich_geoip",
]
