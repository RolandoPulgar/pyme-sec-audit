import platform
import subprocess
from ..rules import Finding, Severity

def run_ps(cmd: str) -> str:
    try:
        res = subprocess.run(["powershell", "-NoProfile", "-Command", cmd], capture_output=True, text=True, timeout=10)
        return res.stdout.strip()
    except Exception:
        return ""

def check_identity_access() -> list:
    findings = []
    is_windows = platform.system().lower() == "windows"

    if not is_windows:
        return findings

    # Check 1: Guest Account Status
    guest_status = run_ps("(Get-LocalUser -Name 'Invitado' -ErrorAction SilentlyContinue).Enabled -or (Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue).Enabled")
    if guest_status.lower() == "true":
        findings.append(Finding(
            id="SEC-IDN-001",
            title="Cuenta de Invitado (Guest) Habilitada",
            category="Identity & Access Control",
            severity=Severity.HIGH,
            description="La cuenta de invitado integrada del sistema operativo está activa.",
            impact="Permite acceso anónimo no auditado a recursos y carpetas compartidas de la empresa.",
            remediation="Deshabilitar la cuenta de invitado: Disable-LocalUser -Name 'Guest' o 'Invitado'.",
            reference="CIS v8 5.1 / ISO 27001 A.9.2.1",
            status="FAIL",
            details="Cuenta Guest/Invitado se encuentra habilitada."
        ))
    else:
        findings.append(Finding(
            id="SEC-IDN-001",
            title="Cuenta de Invitado Correctamente Deshabilitada",
            category="Identity & Access Control",
            severity=Severity.PASSED,
            description="La cuenta de invitado está inactiva, bloqueando accesos anónimos.",
            impact="Reduce la superficie de ataque inicial en la red local.",
            remediation="Mantener la cuenta deshabilitada permanentemente.",
            reference="CIS v8 5.1 / ISO 27001 A.9.2.1",
            status="PASS",
            details="Cuenta Guest/Invitado inactiva o deshabilitada."
        ))

    # Check 2: Local Administrators Count
    admins_raw = run_ps("(Get-LocalGroupMember -Group 'Administradores' -ErrorAction SilentlyContinue).Name")
    if not admins_raw:
        admins_raw = run_ps("(Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue).Name")
    
    admin_list = [a.strip() for a in admins_raw.splitlines() if a.strip()]
    if len(admin_list) > 2:
        findings.append(Finding(
            id="SEC-IDN-002",
            title="Exceso de Cuentas con Privilegios de Administrador Local",
            category="Identity & Access Control",
            severity=Severity.MEDIUM,
            description=f"Se detectaron {len(admin_list)} cuentas en el grupo de Administradores locales.",
            impact="El principio de menor privilegio no se cumple. El uso diario de cuentas de administrador facilita el compromiso ante phishing o descargas maliciosas.",
            remediation="Limitar las cuentas administradoras a 1 cuenta de administración dedicada. Los usuarios deben operar con cuentas estándar sin permisos elevados.",
            reference="CIS v8 5.4 / ISO 27001 A.9.2.3",
            status="FAIL",
            details=f"Administradores locales detectados: {', '.join(admin_list)}"
        ))
    else:
        findings.append(Finding(
            id="SEC-IDN-002",
            title="Cantidad Controlada de Administradores Locales",
            category="Identity & Access Control",
            severity=Severity.PASSED,
            description=f"Se identificaron {len(admin_list)} cuentas administradoras en el equipo.",
            impact="Cumple con las mejores prácticas de segregación y control de privilegios.",
            remediation="Revisar semestralmente los integrantes de los grupos de administración.",
            reference="CIS v8 5.4 / ISO 27001 A.9.2.3",
            status="PASS",
            details=f"Cuentas: {', '.join(admin_list) if admin_list else 'Grupo estándar'}"
        ))

    return findings
