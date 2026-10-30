from ..auditor import AuditResult

def generate_html_report(result: AuditResult, output_path: str):
    score = result.score
    if score >= 80:
        score_color = "#10b981"  # Emerald
        score_bg = "#ecfdf5"
    elif score >= 60:
        score_color = "#f59e0b"  # Amber
        score_bg = "#fffbeb"
    else:
        score_color = "#ef4444"  # Rose
        score_bg = "#fef2f2"

    failed_findings = [f for f in result.findings if f.status == "FAIL"]
    passed_findings = [f for f in result.findings if f.status == "PASS"]

    findings_html = ""
    for f in failed_findings:
        sev = f.severity.value
        sev_badge_color = {
            "CRITICAL": "background-color: #fee2e2; color: #991b1b; border: 1px solid #fecaca;",
            "HIGH": "background-color: #ffedd5; color: #9a3412; border: 1px solid #fed7aa;",
            "MEDIUM": "background-color: #fef3c7; color: #92400e; border: 1px solid #fde68a;",
            "LOW": "background-color: #f1f5f9; color: #475569; border: 1px solid #e2e8f0;"
        }.get(sev, "background-color: #f1f5f9; color: #475569;")

        findings_html += f"""
        <div class="finding-card" style="border-left: 4px solid {score_color};">
            <div class="finding-header">
                <div style="display:flex; align-items:center; gap: 8px;">
                    <span class="badge" style="{sev_badge_color}">{sev}</span>
                    <span class="ref-badge">{f.reference}</span>
                </div>
                <span class="finding-id">{f.id}</span>
            </div>
            <h3 class="finding-title">{f.title}</h3>
            <p class="finding-desc"><strong>Diagnóstico:</strong> {f.description}</p>
            <div class="finding-impact">
                <strong>Impacto de Riesgo para la Empresa:</strong> {f.impact}
            </div>
            <div class="finding-remediation">
                <strong>Plan de Remediación Recomendado:</strong>
                <pre class="code-box">{f.remediation}</pre>
            </div>
            {f'<div class="finding-details"><strong>Detalle técnico:</strong> {f.details}</div>' if f.details else ''}
        </div>
        """

    passed_html = ""
    for f in passed_findings:
        passed_html += f"""
        <div class="passed-item">
            <span class="check-icon">✓</span>
            <div>
                <strong>{f.title}</strong>
                <div style="font-size: 11px; color: #64748b;">{f.reference} &bull; {f.description}</div>
            </div>
        </div>
        """

    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Informe Ejecutivo de Ciberseguridad PyME | {result.hostname}</title>
    <style>
        :root {{
            --primary: #0f172a;
            --accent: #2563eb;
            --bg: #f8fafc;
            --card-bg: #ffffff;
            --text: #1e293b;
            --text-muted: #64748b;
            --border: #e2e8f0;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            line-height: 1.5;
            padding: 32px 16px;
        }}
        .container {{ max-width: 900px; margin: 0 auto; }}
        .header {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 24px;
            margin-bottom: 24px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 16px;
        }}
        .header h1 {{ font-size: 20px; font-weight: 800; color: var(--primary); }}
        .header p {{ font-size: 13px; color: var(--text-muted); margin-top: 4px; }}
        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 12px;
            margin-bottom: 24px;
        }}
        .meta-card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 16px;
            box-shadow: 0 1px 2px rgba(0,0,0,0.03);
        }}
        .meta-card .label {{ font-size: 11px; font-weight: 700; text-transform: uppercase; color: var(--text-muted); }}
        .meta-card .value {{ font-size: 14px; font-weight: 600; color: var(--primary); margin-top: 4px; word-break: break-all; }}
        
        .score-hero {{
            background: {score_bg};
            border: 1px solid {score_color}40;
            border-radius: 16px;
            padding: 24px;
            margin-bottom: 24px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 20px;
        }}
        .score-box {{ display: flex; align-items: baseline; gap: 8px; }}
        .score-number {{ font-size: 54px; font-weight: 900; color: {score_color}; line-height: 1; }}
        .score-denom {{ font-size: 20px; font-weight: 700; color: var(--text-muted); }}
        .score-grade {{ font-size: 18px; font-weight: 800; color: var(--primary); margin-top: 4px; }}
        
        .summary-stats {{
            display: flex;
            gap: 16px;
            flex-wrap: wrap;
        }}
        .stat-pill {{
            background: var(--card-bg);
            padding: 8px 14px;
            border-radius: 10px;
            border: 1px solid var(--border);
            font-size: 12px;
            font-weight: 600;
        }}

        .section-title {{
            font-size: 16px;
            font-weight: 800;
            margin: 28px 0 16px 0;
            color: var(--primary);
            display: flex;
            align-items: center;
            gap: 8px;
        }}

        .finding-card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 16px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.04);
        }}
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        .badge {{
            font-size: 10px;
            font-weight: 800;
            padding: 3px 8px;
            border-radius: 6px;
            text-transform: uppercase;
        }}
        .ref-badge {{
            font-size: 11px;
            font-weight: 600;
            color: var(--text-muted);
            background: #f1f5f9;
            padding: 2px 6px;
            border-radius: 4px;
        }}
        .finding-id {{ font-size: 11px; font-family: monospace; color: var(--text-muted); }}
        .finding-title {{ font-size: 15px; font-weight: 700; color: var(--primary); margin-bottom: 8px; }}
        .finding-desc {{ font-size: 13px; color: var(--text); margin-bottom: 8px; }}
        .finding-impact {{
            background: #f8fafc;
            border: 1px solid var(--border);
            padding: 10px 12px;
            border-radius: 8px;
            font-size: 12px;
            margin-bottom: 10px;
            color: #334155;
        }}
        .finding-remediation {{
            background: #eff6ff;
            border: 1px solid #bfdbfe;
            padding: 10px 12px;
            border-radius: 8px;
            font-size: 12px;
            color: #1e3a8a;
        }}
        .code-box {{
            background: #0f172a;
            color: #f8fafc;
            padding: 8px 12px;
            border-radius: 6px;
            margin-top: 6px;
            font-family: Consolas, monospace;
            font-size: 11px;
            white-space: pre-wrap;
            word-break: break-all;
        }}
        .finding-details {{
            font-size: 11px;
            color: var(--text-muted);
            margin-top: 8px;
            font-family: monospace;
        }}

        .passed-grid {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 16px;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 12px;
        }}
        .passed-item {{
            display: flex;
            align-items: flex-start;
            gap: 10px;
            font-size: 12px;
        }}
        .check-icon {{
            background: #dcfce7;
            color: #15803d;
            border-radius: 50%;
            width: 18px;
            height: 18px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 800;
            font-size: 11px;
            flex-shrink: 0;
            margin-top: 2px;
        }}

        .footer {{
            text-align: center;
            margin-top: 40px;
            font-size: 12px;
            color: var(--text-muted);
            border-top: 1px solid var(--border);
            padding-top: 16px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <div>
                <h1>Informe Ejecutivo de Ciberseguridad PyME</h1>
                <p>Auditoría de Postura y Línea Base de Cumplimiento (CIS Controls &bull; ISO 27001)</p>
            </div>
            <div style="text-align: right;">
                <div style="font-size: 12px; font-weight: 700; color: var(--primary);">Herramienta PyME-Sec-Audit</div>
                <div style="font-size: 11px; color: var(--text-muted);">Auditor: Rolando Pulgar</div>
            </div>
        </div>

        <!-- Meta Grid -->
        <div class="meta-grid">
            <div class="meta-card">
                <div class="label">Dispositivo Auditado</div>
                <div class="value">{result.hostname}</div>
            </div>
            <div class="meta-card">
                <div class="label">Dirección IP</div>
                <div class="value">{result.ip_address}</div>
            </div>
            <div class="meta-card">
                <div class="label">Sistema Operativo</div>
                <div class="value">{result.os_info}</div>
            </div>
            <div class="meta-card">
                <div class="label">Fecha y Hora de Auditoría</div>
                <div class="value">{result.timestamp}</div>
            </div>
        </div>

        <!-- Score Hero -->
        <div class="score-hero">
            <div>
                <div class="score-box">
                    <span class="score-number">{score}</span>
                    <span class="score-denom">/ 100</span>
                </div>
                <div class="score-grade">Nivel de Seguridad: {result.grade}</div>
            </div>
            <div class="summary-stats">
                <div class="stat-pill" style="border-color: #fecaca; color: #991b1b;">
                    Críticos: <strong>{result.summary['CRITICAL']}</strong>
                </div>
                <div class="stat-pill" style="border-color: #fed7aa; color: #9a3412;">
                    Altos: <strong>{result.summary['HIGH']}</strong>
                </div>
                <div class="stat-pill" style="border-color: #fde68a; color: #92400e;">
                    Medios: <strong>{result.summary['MEDIUM']}</strong>
                </div>
                <div class="stat-pill" style="border-color: #bbf7d0; color: #166534;">
                    Aprobados: <strong>{result.summary['PASSED']}</strong>
                </div>
            </div>
        </div>

        <!-- Section: Vulnerabilities & Remediation -->
        <div class="section-title">
            <span>Hallazgos de Seguridad y Plan de Acción Priorizado ({len(failed_findings)})</span>
        </div>
        {findings_html if findings_html else '<p style="color:#10b981; font-weight:600;">No se detectaron fallos de seguridad en las pruebas ejecutadas.</p>'}

        <!-- Section: Passed Controls -->
        <div class="section-title">
            <span>Controles y Buenas Prácticas Verificadas ({len(passed_findings)})</span>
        </div>
        <div class="passed-grid">
            {passed_html}
        </div>

        <!-- Footer -->
        <div class="footer">
            Generado automáticamente con <strong>PyME-Sec-Audit</strong> &bull; Framework de ciberseguridad para pequeñas y medianas empresas.
        </div>
    </div>
</body>
</html>
"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
