from enum import Enum
from dataclasses import dataclass
from typing import Optional, List

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    PASSED = "PASSED"

@dataclass
class Finding:
    id: str
    title: str
    category: str
    severity: Severity
    description: str
    impact: str
    remediation: str
    reference: str  # CIS Control / ISO 27001 control
    status: str     # 'PASS', 'FAIL', 'WARN', 'NOT_APPLICABLE'
    details: Optional[str] = None

SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.INFO: 0,
    Severity.PASSED: 0
}
