import subprocess
import requests
import os
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