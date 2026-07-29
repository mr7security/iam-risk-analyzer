"""
utils/finding.py
Shared Finding dataclass used by all check modules.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    INFO = "INFO"


SEVERITY_WEIGHT = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 20,
    Severity.MEDIUM: 5,
    Severity.INFO: 0,
}


@dataclass
class Finding:
    """A single security finding produced by a check."""

    id: str                          # e.g. "CR-01"
    title: str                       # Short title
    severity: Severity
    description: str                 # What was found and why it matters
    evidence: list[dict[str, Any]]   # Raw data rows to display in the report
    recommendation: str              # What to do about it
    reference: str = ""              # MITRE ATT&CK, CIS, MS Docs URL
    passed: bool = False             # True = check ran and found no issues
    error: str = ""                  # Non-empty if check failed to run
