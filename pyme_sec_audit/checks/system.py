import platform
import subprocess
from ..rules import Finding, Severity

def run_ps(cmd: str) -> str:
    try:
        res = subprocess.run(["powershell", "-NoProfile", "-Command", cmd], capture_output=True, text=True, timeout=10)
        return res.stdout.strip()
    except Exception:
        return ""

def check_system_hygiene() -> list:
    findings = []
    is_windows = platform.system().lower() == "windows"

    if not is_windows:
        return findings

    # Check 1: PowerShell Execution Policy
    policy = run_ps("Get-ExecutionPolicy")
    if policy.lower() in ["unrestricted", "bypass"]:
        findings.append(Finding(
            id="SEC-SYS-001",
            title="Política de Ejecución de PowerShell Insegura (Unrestricted / Bypass)",
            category="System Hygiene",
            severity=Severity.HIGH,
            description=f"La política de ejecución actual de PowerShell es '{policy}'.",
            impact="Permite que scripts .ps1 descargados desde internet o correos se ejecuten sin ninguna advertencia o firma digital.",
            remediation="Configurar la política de ejecución en RemoteSigned: Set-ExecutionPolicy RemoteSigned -Scope LocalMachine",
            reference="CIS v8 2.2 / MITRE ATT&CK T1059.001",
            status="FAIL",
            details=f"ExecutionPolicy: {policy}"
        ))
    else:
        findings.append(Finding(
            id="SEC-SYS-001",
            title="Política de Ejecución de PowerShell Restringida",
            category="System Hygiene",
            severity=Severity.PASSED,
            description=f"La política de ejecución está configurada en '{policy}'.",
            impact="Previene la ejecución no supervisada de scripts no firmados.",
            remediation="Mantener política RemoteSigned o AllSigned.",
            reference="CIS v8 2.2 / MITRE ATT&CK T1059.001",
            status="PASS",
            details=f"ExecutionPolicy: {policy}"
        ))

    # Check 2: Windows Event Log Service status
    eventlog = run_ps("(Get-Service -Name EventLog).Status")
    if eventlog.lower() == "running":
        findings.append(Finding(
            id="SEC-SYS-002",
            title="Servicio de Registro de Eventos (EventLog) Activo",
            category="System Hygiene",
            severity=Severity.PASSED,
            description="El servicio central de auditoría y logs de Windows se encuentra en ejecución.",
            impact="Indispensable para trazabilidad forense, detección de intrusiones y cumplimiento normativo.",
            remediation="Asegurar retención de logs de seguridad por al menos 90 días.",
            reference="CIS v8 8.2 / ISO 27001 A.12.4.1",
            status="PASS",
            details="Servicio EventLog en ejecución."
        ))
    else:
        findings.append(Finding(
            id="SEC-SYS-002",
            title="Servicio de Registro de Eventos Detenido",
            category="System Hygiene",
            severity=Severity.CRITICAL,
            description="El servicio EventLog está detenido o no disponible.",
            impact="El sistema no registra inicios de sesión, accesos fallidos ni alertas de seguridad.",
            remediation="Iniciar y configurar el servicio en automático: Start-Service EventLog; Set-Service EventLog -StartupType Automatic",
            reference="CIS v8 8.2 / ISO 27001 A.12.4.1",
            status="FAIL",
            details=f"Estado del servicio: {eventlog or 'No detectado'}"
        ))

    return findings
