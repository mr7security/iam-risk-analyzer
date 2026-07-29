"""
utils/scoring.py
Calculates an overall risk score (0–100) from a list of findings.

Scoring model:
  - Start at 0 (best)
  - Each CRITICAL finding adds 40 points (capped)
  - Each HIGH adds 20, MEDIUM adds 5, INFO adds 0
  - Score is capped at 100
  - Label: 0–25 LOW | 26–50 MEDIUM | 51–75 HIGH | 76–100 CRITICAL
"""

from utils.finding import Finding, Severity, SEVERITY_WEIGHT


def calculate_score(findings: list[Finding]) -> dict:
    """
    Returns a dict with:
        value: int (0–100)
        label: str (LOW | MEDIUM | HIGH | CRITICAL)
        badge_color: str (CSS hex)
        counts: dict per severity
    """
    counts = {s: 0 for s in Severity}

    for f in findings:
        if not f.passed and not f.error:
            counts[f.severity] += 1

    raw = sum(SEVERITY_WEIGHT[sev] * count for sev, count in counts.items())
    score = min(raw, 100)

    if score <= 25:
        label, color = "LOW", "#3fb950"
    elif score <= 50:
        label, color = "MEDIUM", "#d29922"
    elif score <= 75:
        label, color = "HIGH", "#f85149"
    else:
        label, color = "CRITICAL", "#ff0000"

    return {
        "value": score,
        "label": label,
        "badge_color": color,
        "counts": {s.value: counts[s] for s in Severity},
    }
