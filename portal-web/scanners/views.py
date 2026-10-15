from django.shortcuts import render

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .tasks import run_nmap_scan, run_gobuster_scan, run_nuclei_scan

class TriggerScanView(APIView):
    """
    Endpoint para disparar scans assíncronos (Nmap, Gobuster, Nuclei)
    """
    def post(self, request):
        scan_type = request.data.get("scan_type")
        target = request.data.get("target")

        if not target or not scan_type:
            return Response(
                {"error": "Parâmetros 'target' e 'scan_type' são obrigatórios."},
                status=status.HTTP_400_BAD_REQUEST
            )

        if scan_type == "nmap":
            task = run_nmap_scan.delay(target)
        elif scan_type == "gobuster":
            task = run_gobuster_scan.delay(target)
        elif scan_type == "nuclei":
            task = run_nuclei_scan.delay(target)
        else:
            return Response(
                {"error": "Tipo de scan inválido. Use: nmap, gobuster ou nuclei."},
                status=status.HTTP_400_BAD_REQUEST
            )

        return Response({
            "message": f"Scan {scan_type} iniciado com sucesso para {target}.",
            "task_id": task.id
        }, status=status.HTTP_202_ACCEPTED)
