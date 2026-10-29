import subprocess
import requests
import os
import json
from django.utils import timezone
from celery import shared_task
from .models import Scan
from .validators import validate_target, validate_ip_or_cidr, InvalidTargetError

DEFECTDOJO_URL = os.environ.get('DEFECTDOJO_URL', 'http://defectdojo-nginx:8080')
DEFECTDOJO_API_KEY = os.environ.get('DEFECTDOJO_API_KEY', '')

# Wordlist padrão do Gobuster (baixada no Dockerfile).
GOBUSTER_WORDLIST = os.environ.get(
    'GOBUSTER_WORDLIST',
    '/opt/wordlists/common.txt',
)

# Taxa de pacotes por segundo do Masscan (evita sobrecarregar a rede).
MASSCAN_RATE = int(os.environ.get('MASSCAN_RATE', '1000'))

# Tempo máximo (segundos) para cada ferramenta externa não travar o worker.
SCAN_TIMEOUT = int(os.environ.get('SCAN_TIMEOUT', '1800'))


def _finish(scan, status, output):
    scan.status = status
    scan.output = output
    scan.finished_at = timezone.now()
    scan.save(update_fields=['status', 'output', 'finished_at'])


@shared_task(bind=True)
def run_nmap_scan(self, scan_id):
    """Executa Nmap para um registro Scan existente e exporta ao DefectDojo."""
    try:
        scan = Scan.objects.get(id=scan_id)
    except Scan.DoesNotExist:
        return f"Scan {scan_id} não encontrado."

    scan.status = 'RUNNING'
    scan.task_id = self.request.id
    scan.save(update_fields=['status', 'task_id'])

    xml_file = f"/tmp/scan_{scan_id}.xml"
    try:
        target = validate_target(scan.target, allow_url=False)
        # O alvo já foi validado por validate_target (não pode começar com '-').
        command = ["nmap", "-F", "-oX", xml_file, target]
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=SCAN_TIMEOUT
        )

        _finish(scan, 'COMPLETED', result.stdout or result.stderr)

        if DEFECTDOJO_API_KEY and os.path.exists(xml_file):
            upload_to_defectdojo(xml_file, 'Nmap Scan')

        return f"Scan {scan_id} concluído."

    except InvalidTargetError as e:
        _finish(scan, 'FAILED', f"Alvo inválido: {e}")
        return f"Erro no Scan {scan_id}: {e}"
    except subprocess.TimeoutExpired:
        _finish(scan, 'FAILED', "Tempo limite excedido.")
        return f"Scan {scan_id} excedeu o tempo limite."
    except Exception as e:
        _finish(scan, 'FAILED', str(e))
        return f"Erro no Scan {scan_id}: {e}"
    finally:
        if os.path.exists(xml_file):
            os.remove(xml_file)


@shared_task(bind=True)
def run_gobuster_scan(self, scan_id):
    """Enumeração de diretórios com Gobuster para um registro Scan existente."""
    try:
        scan = Scan.objects.get(id=scan_id)
    except Scan.DoesNotExist:
        return f"Scan {scan_id} não encontrado."

    scan.status = 'RUNNING'
    scan.task_id = self.request.id
    scan.save(update_fields=['status', 'task_id'])

    out_file = f"/tmp/gobuster_{scan_id}.txt"
    try:
        target = validate_target(scan.target, allow_url=True)
        cmd = [
            "gobuster", "dir",
            "-u", target,
            "-w", GOBUSTER_WORDLIST,
            "-o", out_file,
            "-q", "--no-error",
        ]
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT
        )

        output = ""
        if os.path.exists(out_file):
            with open(out_file, "r") as f:
                output = f.read()
        output = output or result.stdout or result.stderr

        _finish(scan, 'COMPLETED', output)

        if DEFECTDOJO_API_KEY and os.path.exists(out_file):
            upload_to_defectdojo(out_file, 'Gobuster Scan')

        return f"Scan {scan_id} concluído."

    except InvalidTargetError as e:
        _finish(scan, 'FAILED', f"Alvo inválido: {e}")
        return f"Erro no Scan {scan_id}: {e}"
    except subprocess.TimeoutExpired:
        _finish(scan, 'FAILED', "Tempo limite excedido.")
        return f"Scan {scan_id} excedeu o tempo limite."
    except Exception as e:
        _finish(scan, 'FAILED', str(e))
        return f"Erro no Scan {scan_id}: {e}"
    finally:
        if os.path.exists(out_file):
            os.remove(out_file)


@shared_task(bind=True)
def run_nuclei_scan(self, scan_id):
    """Varredura de vulnerabilidades com Nuclei (saída JSONL)."""
    try:
        scan = Scan.objects.get(id=scan_id)
    except Scan.DoesNotExist:
        return f"Scan {scan_id} não encontrado."

    scan.status = 'RUNNING'
    scan.task_id = self.request.id
    scan.save(update_fields=['status', 'task_id'])

    output_file = f"/tmp/nuclei_{scan_id}.jsonl"
    try:
        target = validate_target(scan.target, allow_url=True)
        # -json-export grava JSON Lines (um achado por linha) no Nuclei v3.
        cmd = [
            "nuclei",
            "-target", target,
            "-severity", "low,medium,high,critical",
            "-json-export", output_file,
            "-silent",
            "-duc",
        ]
        # check=False: o Nuclei retorna exit code != 0 em cenários normais.
        subprocess.run(
            cmd, capture_output=True, text=True, check=False, timeout=SCAN_TIMEOUT
        )

        findings = []
        if os.path.exists(output_file):
            with open(output_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            findings.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue

            if DEFECTDOJO_API_KEY:
                upload_to_defectdojo(output_file, scan_type='Nuclei Scan')

        summary = {
            "target": target,
            "total_vulnerabilities": len(findings),
            "findings": findings,
        }
        _finish(scan, 'COMPLETED', json.dumps(summary, ensure_ascii=False, indent=2))
        return f"Scan {scan_id} concluído com {len(findings)} achado(s)."

    except InvalidTargetError as e:
        _finish(scan, 'FAILED', f"Alvo inválido: {e}")
        return f"Erro no Scan {scan_id}: {e}"
    except subprocess.TimeoutExpired:
        _finish(scan, 'FAILED', "Tempo limite excedido.")
        return f"Scan {scan_id} excedeu o tempo limite."
    except Exception as e:
        _finish(scan, 'FAILED', str(e))
        return f"Erro no Scan {scan_id}: {e}"
    finally:
        if os.path.exists(output_file):
            os.remove(output_file)


@shared_task(bind=True)
def run_masscan_scan(self, scan_id):
    """Varredura rápida de portas TCP com Masscan (saída XML, taxa limitada)."""
    try:
        scan = Scan.objects.get(id=scan_id)
    except Scan.DoesNotExist:
        return f"Scan {scan_id} não encontrado."

    scan.status = 'RUNNING'
    scan.task_id = self.request.id
    scan.save(update_fields=['status', 'task_id'])

    xml_file = f"/tmp/masscan_{scan_id}.xml"
    try:
        target = validate_ip_or_cidr(scan.target)
        # Portas 1-1000 e taxa de 1000 pps: escopo e carga controlados.
        cmd = [
            "masscan", target,
            "-p1-1000",
            "--rate", str(MASSCAN_RATE),
            "-oX", xml_file,
        ]
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT
        )

        output = ""
        if os.path.exists(xml_file):
            with open(xml_file, "r") as f:
                output = f.read()
        output = output or result.stdout or result.stderr

        _finish(scan, 'COMPLETED', output)

        if DEFECTDOJO_API_KEY and os.path.exists(xml_file):
            upload_to_defectdojo(xml_file, 'Masscan Scan')

        return f"Scan {scan_id} concluído."

    except InvalidTargetError as e:
        _finish(scan, 'FAILED', f"Alvo inválido: {e}")
        return f"Erro no Scan {scan_id}: {e}"
    except subprocess.TimeoutExpired:
        _finish(scan, 'FAILED', "Tempo limite excedido.")
        return f"Scan {scan_id} excedeu o tempo limite."
    except Exception as e:
        _finish(scan, 'FAILED', str(e))
        return f"Erro no Scan {scan_id}: {e}"
    finally:
        if os.path.exists(xml_file):
            os.remove(xml_file)


def upload_to_defectdojo(file_path, scan_type='Nmap Scan'):
    """Importa um relatório para o DefectDojo via API v2."""
    if not DEFECTDOJO_API_KEY:
        return

    headers = {'Authorization': f'Token {DEFECTDOJO_API_KEY}'}
    endpoint = f"{DEFECTDOJO_URL}/api/v2/import-scan/"

    try:
        with open(file_path, 'rb') as f:
            files = {'file': f}
            data = {
                'scan_type': scan_type,
                'active': 'true',
                'verified': 'true',
                'minimum_severity': 'Info',
                'engagement_name': 'Automated Scans',
                'product_name': 'Portal PSU',
                'auto_create_context': 'true',
            }
            response = requests.post(
                endpoint, headers=headers, data=data, files=files, timeout=60
            )
            if response.status_code >= 400:
                print(
                    f"[!] DefectDojo respondeu {response.status_code}: "
                    f"{response.text[:300]}"
                )
    except Exception as e:
        print(f"[!] Erro no envio ao DefectDojo: {e}")

