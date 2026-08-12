import subprocess
from celery import shared_task
from .models import Scan

@shared_task
def run_nmap_scan(scan_id):
    try:
        scan = Scan.objects.get(id=scan_id)
        scan.status = 'RUNNING'
        scan.save()

        # Executa o Nmap no alvo e gera o output XML
        xml_file = f"/tmp/scan_{scan_id}.xml"
        command = ["nmap", "-F", "-oX", xml_file, scan.target]
        result = subprocess.run(command, capture_output=True, text=True)

        scan.status = 'COMPLETED'
        scan.output = result.stdout
        scan.save()
        return f"Scan {scan_id} finalizado com sucesso."

    except Exception as e:
        scan.status = 'FAILED'
        scan.output = str(e)
        scan.save()
        return f"Erro no Scan {scan_id}: {str(e)}"