import os
import socket
import platform
import datetime
from dataclasses import dataclass, field
from typing import List, Dict
from .rules import Finding, Severity, SEVERITY_WEIGHTS
from .checks import (
    check_endpoint_security,
    check_identity_access,
    check_network_exposure,
    check_system_hygiene
)

@dataclass
class AuditResult:
    hostname: str
    ip_address: str
    os_info: str
    timestamp: str
    score: int
    grade: str
    summary: Dict[str, int]
    findings: List[Finding] = field(default_factory=list)

class PyMESecAuditor:
    def __init__(self):
        self.findings: List[Finding] = []

    def run_all(self) -> AuditResult:
        self.findings = []
        
        # Execute check modules
        self.findings.extend(check_endpoint_security())
        self.findings.extend(check_identity_access())
        self.findings.extend(check_network_exposure())
        self.findings.extend(check_system_hygiene())

        # Calculate metrics
        summary = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "PASSED": 0,
            "TOTAL_CHECKS": len(self.findings)
        }

        penalty = 0
        for f in self.findings:
            if f.status == "FAIL":
                sev_name = f.severity.value
                if sev_name in summary:
                    summary[sev_name] += 1
                penalty += SEVERITY_WEIGHTS.get(f.severity, 0)
            elif f.status == "PASS":
                summary["PASSED"] += 1

        # Base score 100 minus penalties (bounded [0, 100])
        score = max(0, min(100, 100 - penalty))

        # Letter Grade
        if score >= 90:
            grade = "A (Excelente)"
        elif score >= 75:
            grade = "B (Bueno - Riesgo Bajo)"
        elif score >= 60:
            grade = "C (Aceptable - Requiere Atención)"
        elif score >= 40:
            grade = "D (Deficiente - Riesgo Alto)"
        else:
            grade = "F (Crítico - Vulnerable a Intrusiones)"

        # Host metadata
        hostname = socket.gethostname()
        try:
            ip = socket.gethostbyname(hostname)
        except Exception:
            ip = "127.0.0.1"

        os_info = f"{platform.system()} {platform.release()} (Build {platform.version()})"
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        return AuditResult(
            hostname=hostname,
            ip_address=ip,
            os_info=os_info,
            timestamp=timestamp,
            score=score,
            grade=grade,
            summary=summary,
            findings=self.findings
        )
