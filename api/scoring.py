"""
SentinelLog API: Detection Scoring, Baseline Novelty, and Alert Suppression Engine.
Combines signature rules, supervised ML attack probabilities, Isolation Forest anomaly scores,
and host baseline novelty into an explainable 0-100 severity rating.
"""

from collections import defaultdict
import time
from typing import Any
import uuid

SEVERITY_LEVELS = [
    (80, "CRITICAL"),
    (60, "HIGH"),
    (40, "MEDIUM"),
    (20, "LOW"),
    (0, "INFO"),
]


def score_to_level(score: float) -> str:
    """Maps continuous 0-100 score to discrete operational severity level."""
    for threshold, level in SEVERITY_LEVELS:
        if score >= threshold:
            return level
    return "INFO"


def calculate_severity(
    rule_hits: list[dict[str, Any]] | None = None,
    ml_prob: float = 0.0,
    anomaly: float = 0.0,
    baseline_novelty: bool = False,
    allowlisted: bool = False,
) -> tuple[float, str, list[str]]:
    """
    Computes a composite explainable security severity score (0-100).
    
    Formula:
        Score = 0.60 * TopRuleSeverity + 25 * MLProb + 10 * AnomalyScore + 5 * Novelty + 10 * AgreementBonus
    """
    if allowlisted:
        return 0.0, "INFO", ["Entity or pattern present on allowlist"]

    score = 0.0
    reasons = []

    # 1. Rule Signatures (Max 60 points)
    if rule_hits:
        top_rule_sev = max((r.get("severity", 50) for r in rule_hits), default=0)
        score += top_rule_sev * 0.60
        for r in rule_hits:
            reasons.append(f"{r.get('id', 'RULE')}: {r.get('name', 'Signature match')}")

    # 2. Supervised ML Probability (Max 25 points)
    score += ml_prob * 25.0
    if ml_prob >= 0.70:
        reasons.append(f"ML Classifier high attack probability ({ml_prob:.2f})")

    # 3. Unsupervised Isolation Forest Anomaly (Max 10 points)
    score += anomaly * 10.0
    if anomaly >= 0.70:
        reasons.append(f"Unsupervised statistical outlier ({anomaly:.2f})")

    # 4. Host Baseline Novelty (5 points)
    if baseline_novelty:
        score += 5.0
        reasons.append("Novel activity: first time seen on this endpoint")

    # 5. Independent Layer Agreement Bonus (10 points)
    if rule_hits and ml_prob >= 0.70:
        score += 10.0
        reasons.append("Convergence bonus: Rule signature and ML prediction independently agree")

    final_score = min(100.0, max(0.0, round(score, 1)))
    level = score_to_level(final_score)

    if not reasons:
        reasons.append("Routine benign activity")

    return final_score, level, reasons


class AlertSuppressionEngine:
    """
    Suppresses duplicate alerts for the same entity and rule within a temporal window
    (default 10 minutes) to prevent security analyst alert fatigue.
    """

    def __init__(self, suppression_window_seconds: float = 600.0):
        self.window = suppression_window_seconds
        # Key: (host, rule_id, target) -> (last_timestamp, alert_id, count)
        self.active_alerts: dict[tuple[str, str, str], tuple[float, str, int]] = {}

    def process_alert(
        self,
        host: str,
        rule_id: str,
        target: str,
    ) -> tuple[bool, str, int]:
        """
        Returns:
            tuple of (is_suppressed, alert_id, count)
        """
        now = time.time()
        key = (host, rule_id, target or "unknown")

        if key in self.active_alerts:
            last_ts, alert_id, count = self.active_alerts[key]
            if now - last_ts <= self.window:
                # Suppress new alert and increment count
                new_count = count + 1
                self.active_alerts[key] = (now, alert_id, new_count)
                return True, alert_id, new_count

        # Raise fresh alert
        new_alert_id = f"alert-{uuid.uuid4().hex[:12]}"
        self.active_alerts[key] = (now, new_alert_id, 1)
        return False, new_alert_id, 1


class BaselineStore:
    """
    Maintains a profile of established activities per host
    (known binaries, destination IPs).
    """

    def __init__(self):
        # host -> set of (item_type, item_value)
        self.host_baselines: dict[str, set[tuple[str, str]]] = defaultdict(set)

    def check_and_record_novelty(self, host: str, item_type: str, item_value: str) -> bool:
        """
        Returns True if (item_type, item_value) is observed on this host for the first time.
        """
        if not item_value:
            return False
        key = (item_type, item_value.lower())
        if key not in self.host_baselines[host]:
            self.host_baselines[host].add(key)
            return True
        return False
