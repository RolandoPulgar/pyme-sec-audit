import platform
import subprocess
from ..rules import Finding, Severity

def run_ps(cmd: str) -> str:
    try:
        res = subprocess.run(["powershell", "-NoProfile", "-Command", cmd], capture_output=True, text=True, timeout=10)
        return res.stdout.strip()
    except Exception:
        return ""

def check_endpoint_security() -> list:
    findings = []
    is_windows = platform.system().lower() == "windows"

    if not is_windows:
        findings.append(Finding(
            id="SEC-END-000",
            title="Soporte de Plataforma Endpoint",
            category="Endpoint Protection",
            severity=Severity.INFO,
            description="La auditoría de endpoints detallada de Windows se omite en este sistema operativo.",
            impact="Información de plataforma.",
            remediation="N/A",
            reference="CIS v8 Control 10",
            status="NOT_APPLICABLE",
            details=f"Sistema operativo: {platform.system()}"
        ))
        return findings

    # Check 1: Antivirus / Windows Defender Real-time Protection
    av_status = run_ps("(Get-MpComputerStatus).RealTimeProtectionEnabled")
    if av_status.lower() == "true":
        findings.append(Finding(
            id="SEC-END-001",
            title="Protección Antivirus en Tiempo Real",
            category="Endpoint Protection",
            severity=Severity.PASSED,
            description="La protección antivirus en tiempo real está habilitada y activa.",
            impact="Protege contra ejecución de malware conocido, troyanos y ransomware.",
            remediation="Mantener definiciones de antivirus al día.",
            reference="CIS v8 10.1 / ISO 27001 A.12.2.1",
            status="PASS",
            details="Windows Defender RealTimeProtection activo."
        ))
    else:
        findings.append(Finding(
            id="SEC-END-001",
            title="Protección Antivirus en Tiempo Real Deshabilitada",
            category="Endpoint Protection",
            severity=Severity.CRITICAL,
            description="No se detectó protección antivirus en tiempo real activa en el equipo.",
            impact="Riesgo crítico de infección por ransomware, ladrones de credenciales y troyanos sin detección.",
            remediation="Activar Windows Defender inmediatamente: Set-MpPreference -DisableRealtimeMonitoring $false o instalar solución EDR corporativa.",
            reference="CIS v8 10.1 / ISO 27001 A.12.2.1",
            status="FAIL",
            details=f"Estado retornado: {av_status or 'Desconocido / Inactivo'}"
        ))

    # Check 2: Windows Firewall Status across all profiles
    fw_status = run_ps("(Get-NetFirewallProfile).Enabled -contains $false")
    if fw_status.lower() == "true":
        findings.append(Finding(
            id="SEC-END-002",
            title="Firewall del Sistema Incompleto o Desactivado",
            category="Endpoint Protection",
            severity=Severity.HIGH,
            description="Al menos uno de los perfiles del Firewall (Dominio, Privado o Público) está desactivado.",
            impact="Permite conexiones entrantes no deseadas y facilita el movimiento lateral de atacantes en la red local.",
            remediation="Habilitar todos los perfiles de firewall: Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True",
            reference="CIS v8 4.4 / ISO 27001 A.13.1.1",
            status="FAIL",
            details="Perfiles de firewall desactivados detectados."
        ))
    else:
        findings.append(Finding(
            id="SEC-END-002",
            title="Firewall de Windows Activo en Todos los Perfiles",
            category="Endpoint Protection",
            severity=Severity.PASSED,
            description="Los perfiles de firewall Dominio, Privado y Público están correctamente habilitados.",
            impact="Aísla el equipo de escaneos y ataques de red externa o lateral.",
            remediation="Auditar periódicamente las reglas de firewall entrantes.",
            reference="CIS v8 4.4 / ISO 27001 A.13.1.1",
            status="PASS",
            details="Todos los perfiles de firewall están activos."
        ))

    # Check 3: BitLocker Disk Encryption (Drive C:)
    bitlocker = run_ps("(Get-BitLockerVolume -MountPoint 'C:' -ErrorAction SilentlyContinue).ProtectionStatus")
    if bitlocker.strip() == "1" or bitlocker.lower() == "on":
        findings.append(Finding(
            id="SEC-END-003",
            title="Cifrado de Disco (BitLocker) Activo",
            category="Endpoint Protection",
            severity=Severity.PASSED,
            description="La unidad del sistema operativo (C:) cuenta con protección de cifrado de volumen BitLocker.",
            impact="Protege los datos confidenciales de la empresa en caso de robo o pérdida física del dispositivo.",
            remediation="Asegurar resguardo seguro de las claves de recuperación en repositorio centralizado.",
            reference="CIS v8 3.11 / ISO 27001 A.10.1.1",
            status="PASS",
            details="Unidad C: cifrada con BitLocker."
        ))
    else:
        findings.append(Finding(
            id="SEC-END-003",
            title="Unidad del Sistema sin Cifrado de Disco (BitLocker)",
            category="Endpoint Protection",
            severity=Severity.MEDIUM,
            description="La unidad principal no tiene el cifrado BitLocker activo.",
            impact="Cualquier persona con acceso físico al equipo puede extraer el disco y leer archivos sin contraseña de Windows.",
            remediation="Habilitar BitLocker en la unidad C: mediante Manage-Bde o Panel de Control.",
            reference="CIS v8 3.11 / ISO 27001 A.10.1.1",
            status="FAIL",
            details="BitLocker inactivo en unidad C:."
        ))

    # Check 4: UAC (User Account Control)
    uac = run_ps("(Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA")
    if str(uac).strip() == "1":
        findings.append(Finding(
            id="SEC-END-004",
            title="Control de Cuentas de Usuario (UAC) Habilitado",
            category="Endpoint Protection",
            severity=Severity.PASSED,
            description="UAC está activado para impedir que software no autorizado realice cambios en el sistema.",
            impact="Mitiga elevaciones automáticas de privilegios por malware.",
            remediation="Mantener el nivel de notificación en predeterminado o superior.",
            reference="CIS v8 5.4 / ISO 27001 A.9.4.1",
            status="PASS",
            details="EnableLUA = 1"
        ))
    else:
        findings.append(Finding(
            id="SEC-END-004",
            title="Control de Cuentas de Usuario (UAC) Desactivado",
            category="Endpoint Protection",
            severity=Severity.HIGH,
            description="UAC se encuentra desactivado, permitiendo que cualquier programa ejecute acciones administrativas silenciosas.",
            impact="Riesgo de compromiso total silencioso por troyanos.",
            remediation="Activar UAC configurando EnableLUA en 1 en el registro.",
            reference="CIS v8 5.4 / ISO 27001 A.9.4.1",
            status="FAIL",
            details="EnableLUA = 0 o no encontrado."
        ))

    return findings
