from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated

from .models import Scan
from .validators import validate_target, InvalidTargetError
from .tasks import run_nmap_scan, run_gobuster_scan, run_nuclei_scan

SCAN_DISPATCH = {
    "nmap": run_nmap_scan,
    "gobuster": run_gobuster_scan,
    "nuclei": run_nuclei_scan,
}


class TriggerScanView(APIView):
    """
    Dispara scans assíncronos (Nmap, Gobuster, Nuclei).

    POST /api/scan/start/
    Body: {"scan_type": "nmap|gobuster|nuclei", "target": "<ip|dominio|url>"}
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        scan_type = request.data.get("scan_type")
        target = request.data.get("target")

        if not target or not scan_type:
            return Response(
                {"error": "Parâmetros 'target' e 'scan_type' são obrigatórios."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if scan_type not in SCAN_DISPATCH:
            return Response(
                {"error": "Tipo de scan inválido. Use: nmap, gobuster ou nuclei."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Validação de segurança (impede injeção de argumentos).
        allow_url = scan_type != "nmap"
        try:
            target = validate_target(target, allow_url=allow_url)
        except InvalidTargetError as e:
            return Response(
                {"error": f"Alvo inválido: {e}"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        scan = Scan.objects.create(target=target, scan_type=scan_type)
        task = SCAN_DISPATCH[scan_type].delay(scan.id)

        scan.task_id = task.id
        scan.save(update_fields=["task_id"])

        return Response(
            {
                "status": "scan_initiated",
                "scan_id": scan.id,
                "task_id": task.id,
                "target": target,
                "scan_type": scan_type,
            },
            status=status.HTTP_202_ACCEPTED,
        )


class ScanStatusView(APIView):
    """GET /api/scan/<scan_id>/ - consulta status e resultado de um scan."""
    permission_classes = [IsAuthenticated]

    def get(self, request, scan_id):
        try:
            scan = Scan.objects.get(id=scan_id)
        except Scan.DoesNotExist:
            return Response(
                {"error": "Scan não encontrado."},
                status=status.HTTP_404_NOT_FOUND,
            )

        return Response(
            {
                "scan_id": scan.id,
                "scan_type": scan.scan_type,
                "target": scan.target,
                "status": scan.status,
                "task_id": scan.task_id,
                "created_at": scan.created_at,
                "finished_at": scan.finished_at,
                "output": scan.output,
            },
            status=status.HTTP_200_OK,
        )

