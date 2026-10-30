import sys
import argparse

# Ensure utf-8 output encoding on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from .auditor import PyMESecAuditor
from .reporters import generate_html_report, generate_json_report

def main():
    parser = argparse.ArgumentParser(
        description="PyME-Sec-Audit: Herramienta de Auditoría y Línea Base de Ciberseguridad para PyMEs."
    )
    parser.add_argument(
        "--format", "-f",
        choices=["html", "json", "all"],
        default="html",
        help="Formato del informe a generar (html, json, o all)."
    )
    parser.add_argument(
        "--output", "-o",
        default="reporte_seguridad_pyme.html",
        help="Ruta del archivo de salida del informe."
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Modo silencioso, omite la salida en consola."
    )

    args = parser.parse_args()

    if not args.quiet:
        print("\n" + "=" * 65)
        print("  [+] PyME-Sec-Audit v1.0.0 | SME Cybersecurity Baseline Auditor")
        print("      Autor: Rolando Pulgar")
        print("=" * 65)
        print("[*] Iniciando diagnóstico de seguridad del endpoint...")

    auditor = PyMESecAuditor()
    result = auditor.run_all()

    if not args.quiet:
        print(f"[+] Equipo auditado    : {result.hostname} ({result.ip_address})")
        print(f"[+] Sistema operativo  : {result.os_info}")
        print(f"[+] Puntuacion Final   : {result.score} / 100")
        print(f"[+] Diagnostico Global : {result.grade}")
        print("-" * 65)
        print(f"    - Criticos : {result.summary['CRITICAL']}")
        print(f"    - Altos    : {result.summary['HIGH']}")
        print(f"    - Medios   : {result.summary['MEDIUM']}")
        print(f"    - Aprobados: {result.summary['PASSED']}")
        print("-" * 65)

    # Generate Reports
    if args.format in ["html", "all"]:
        html_out = args.output if args.output.endswith(".html") else f"{args.output}.html"
        generate_html_report(result, html_out)
        if not args.quiet:
            print(f"[OK] Informe Ejecutivo HTML generado: {html_out}")

    if args.format in ["json", "all"]:
        json_out = args.output.replace(".html", ".json") if args.output.endswith(".html") else f"{args.output}.json"
        generate_json_report(result, json_out)
        if not args.quiet:
            print(f"[OK] Informe Tecnico JSON generado   : {json_out}")

    if not args.quiet:
        print("\n[*] Diagnostico completado exitosamente.\n")

if __name__ == "__main__":
    main()
