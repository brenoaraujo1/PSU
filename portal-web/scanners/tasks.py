import subprocess
import requests
import os
import json
from celery import shared_task
from .models import Scan

DEFECTDOJO_URL = os.environ.get('DEFECTDOJO_URL', 'http://defectdojo:8080')
DEFECTDOJO_API_KEY = os.environ.get('DEFECTDOJO_API_KEY', '')

@shared_task
def run_nmap_scan(scan_id):
    try:
        scan = Scan.objects.get(id=scan_id)
        scan.status = 'RUNNING'
        scan.save()

        xml_file = f"/tmp/scan_{scan_id}.xml"
        command = ["nmap", "-F", "-oX", xml_file, scan.target]
        result = subprocess.run(command, capture_output=True, text=True)

        scan.status = 'COMPLETED'
        scan.output = result.stdout
        scan.save()

        # Envia para o DefectDojo se a chave de API estiver configurada
        if DEFECTDOJO_API_KEY:
            upload_to_defectdojo(xml_file, scan.target)

        return f"Scan {scan_id} concluído."

    except Exception as e:
        scan.status = 'FAILED'
        scan.output = str(e)
        scan.save()
        return f"Erro no Scan {scan_id}: {str(e)}"

def upload_to_defectdojo(file_path, target):
    headers = {'Authorization': f'Token {DEFECTDOJO_API_KEY}'}
    endpoint = f"{DEFECTDOJO_URL}/api/v2/import-scan/"
    
    with open(file_path, 'rb') as f:
        files = {'file': f}
        data = {
            'scan_type': 'Nmap Scan',
            'active': 'true',
            'verified': 'true',
            'minimum_severity': 'Info',
            'engagement_name': 'Automated Scans',
            'product_name': 'Portal PSU',
            'auto_create_context': 'true'
        }
        requests.post(endpoint, headers=headers, data=data, files=files)

@shared_task
def run_gobuster_scan(target_url, wordlist_path="/usr/share/wordlists/dirb/common.txt"):
    """
    Executa enumeração de diretórios com Gobuster e retorna os caminhos encontrados.
    """
    cmd = [
        "gobuster", "dir",
        "-u", target_url,
        "-w", wordlist_path,
        "-q",
        "--no-error"
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return {"target": target_url, "output": result.stdout}
    except subprocess.CalledProcessError as e:
        return {"error": e.stderr or str(e)}

@shared_task
def run_nuclei_scan(target):
    """
    Executa varredura de vulnerabilidades com Nuclei e gera saída estruturada em JSON.
    """
    output_file = f"/tmp/nuclei_{target.replace('/', '_')}.json"
    cmd = [
        "nuclei",
        "-u", target,
        "-severity", "low,medium,high,critical",
        "-json-export", output_file,
        "-silent"
    ]
    try:
        subprocess.run(cmd, capture_output=True, text=True, check=True)
        
        findings = []
        if os.path.exists(output_file):
            with open(output_file, "r") as f:
                for line in f:
                    if line.strip():
                        findings.append(json.loads(line))
            os.remove(output_file)
            
        return {"target": target, "total_vulnerabilities": len(findings), "findings": findings}
    except Exception as e:
        return {"error": str(e)}