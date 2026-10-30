import json
from ..auditor import AuditResult

def generate_json_report(result: AuditResult, output_path: str):
    data = {
        "metadata": {
            "tool": "PyME-Sec-Audit",
            "version": "1.0.0",
            "hostname": result.hostname,
            "ip_address": result.ip_address,
            "os_info": result.os_info,
            "timestamp": result.timestamp
        },
        "score": {
            "numerical": result.score,
            "grade": result.grade,
            "summary": result.summary
        },
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "category": f.category,
                "severity": f.severity.value,
                "status": f.status,
                "reference": f.reference,
                "description": f.description,
                "impact": f.impact,
                "remediation": f.remediation,
                "details": f.details
            } for f in result.findings
        ]
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
