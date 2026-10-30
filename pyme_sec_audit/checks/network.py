import socket
import platform
import subprocess
from ..rules import Finding, Severity

RISKY_PORTS = {
    21: ("FTP", Severity.HIGH, "Protocolo de transferencia de archivos en texto claro sin cifrado."),
    23: ("Telnet", Severity.CRITICAL, "Protocolo de administración remota inseguro en texto claro."),
    445: ("SMB (Direct-TCP)", Severity.HIGH, "Vector principal de propagación de ransomware y explotación (ej: EternalBlue)."),
    3389: ("RDP (Escritorio Remoto)", Severity.MEDIUM, "Servicio de escritorio remoto escuchando. Riesgo de ataques de fuerza bruta si no tiene NLA o MFA."),
    5900: ("VNC", Severity.HIGH, "Servicio de control remoto comúnmente configurado con autenticación débil.")
}

def is_port_listening(port: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.4)
    try:
        s.connect(('127.0.0.1', port))
        s.close()
        return True
    except Exception:
        return False

def check_network_exposure() -> list:
    findings = []

    # Check listening dangerous ports
    open_risky = []
    for port, (name, severity, desc) in RISKY_PORTS.items():
        if is_port_listening(port):
            open_risky.append((port, name, severity, desc))
            findings.append(Finding(
                id=f"SEC-NET-{port:03d}",
                title=f"Puerto de Red Inseguro Escuchando: {name} (Puerto {port})",
                category="Network Exposure",
                severity=severity,
                description=f"El servicio {name} está escuchando activamente en el puerto {port}.",
                impact=desc,
                remediation=f"Si el servicio no es estrictamente necesario, deshabilitarlo o bloquear el puerto {port} en el Firewall.",
                reference="CIS v8 4.1 / ISO 27001 A.13.1.2",
                status="FAIL",
                details=f"Conexión TCP exitosa a 127.0.0.1:{port}"
            ))

    if not open_risky:
        findings.append(Finding(
            id="SEC-NET-000",
            title="Puertos Críticos Inseguros Cerrados",
            category="Network Exposure",
            severity=Severity.PASSED,
            description="No se detectaron servicios inseguros típicos (Telnet, FTP, VNC) escuchando localmente.",
            impact="Reduce drásticamente la exposición a movimientos laterales en la red de la PyME.",
            remediation="Mantener escaneos de puertos periódicos.",
            reference="CIS v8 4.1 / ISO 27001 A.13.1.2",
            status="PASS",
            details="Puertos 21, 23, 5900 verificados y cerrados."
        ))

    # Check LLMNR (Link-Local Multicast Name Resolution) on Windows
    if platform.system().lower() == "windows":
        try:
            res = subprocess.run([
                "powershell", "-NoProfile", "-Command",
                "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name 'EnableMulticast' -ErrorAction SilentlyContinue).EnableMulticast"
            ], capture_output=True, text=True, timeout=5)
            val = res.stdout.strip()

            if val == "0":
                findings.append(Finding(
                    id="SEC-NET-006",
                    title="Resolución LLMNR Deshabilitada",
                    category="Network Exposure",
                    severity=Severity.PASSED,
                    description="El protocolo vulnerable LLMNR está deshabilitado en las directivas de DNS.",
                    impact="Protege contra ataques de envenenamiento de nombres de red (MITM) y captura de hashes NTLM.",
                    remediation="Mantener EnableMulticast en 0.",
                    reference="CIS v8 4.8 / MITRE ATT&CK T1557.001",
                    status="PASS",
                    details="EnableMulticast = 0"
                ))
            else:
                findings.append(Finding(
                    id="SEC-NET-006",
                    title="Protocolo LLMNR Habilitado (Riesgo de Captura de Credenciales)",
                    category="Network Exposure",
                    severity=Severity.HIGH,
                    description="El protocolo LLMNR se encuentra activo por defecto.",
                    impact="Un atacante conectado a la red Wi-Fi o cableada de la empresa puede usar herramientas como Responder para suplantar servicios y capturar contraseñas en hash NTLM.",
                    remediation="Deshabilitar LLMNR mediante GPO o clave de registro: New-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name 'EnableMulticast' -Value 0 -PropertyType DWord -Force",
                    reference="CIS v8 4.8 / MITRE ATT&CK T1557.001",
                    status="FAIL",
                    details="LLMNR activo (EnableMulticast != 0)"
                ))
        except Exception:
            pass

    return findings
