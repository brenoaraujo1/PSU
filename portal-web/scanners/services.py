"""
Regra única de disparo de scans, usada pela API (views.py) e pelo painel web
(web_views.py). Centraliza a validação do alvo e o enfileiramento da task.
"""
from .models import Scan
from .tasks import run_nmap_scan, run_gobuster_scan, run_nuclei_scan, run_masscan_scan
from .validators import validate_target, validate_ip_or_cidr, InvalidTargetError


class UnknownScanTypeError(ValueError):
    """Tipo de scan não suportado."""


SCAN_DISPATCH = {
    "nmap": run_nmap_scan,
    "gobuster": run_gobuster_scan,
    "nuclei": run_nuclei_scan,
    "masscan": run_masscan_scan,
}

SCAN_LABELS = {
    "nmap": "Nmap",
    "gobuster": "Gobuster",
    "nuclei": "Nuclei",
    "masscan": "Masscan",
}


def normalize_target(scan_type, target):
    """Valida o alvo conforme a ferramenta. Levanta InvalidTargetError."""
    if scan_type == "masscan":
        return validate_ip_or_cidr(target)
    # Nmap não aceita URL; Gobuster e Nuclei aceitam.
    return validate_target(target, allow_url=scan_type != "nmap")


def create_and_dispatch(scan_type, target):
    """
    Valida, cria o registro Scan e enfileira a task no Celery.
    Retorna (scan, task). Levanta UnknownScanTypeError ou InvalidTargetError.
    """
    if scan_type not in SCAN_DISPATCH:
        raise UnknownScanTypeError(
            "Tipo de scan inválido. Use: nmap, gobuster, nuclei ou masscan."
        )

    target = normalize_target(scan_type, target)
    scan = Scan.objects.create(target=target, scan_type=scan_type)
    task = SCAN_DISPATCH[scan_type].delay(scan.id)

    scan.task_id = task.id
    scan.save(update_fields=["task_id"])
    return scan, task
