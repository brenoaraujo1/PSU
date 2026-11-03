from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect, render

from .models import Scan
from .services import SCAN_LABELS, create_and_dispatch, UnknownScanTypeError
from .validators import InvalidTargetError

HISTORY_LIMIT = 50


@login_required
def dashboard(request):
    """Painel: formulário de disparo e histórico recente de scans."""
    if request.method == "POST":
        scan_type = request.POST.get("scan_type", "")
        target = request.POST.get("target", "").strip()
        try:
            scan, _ = create_and_dispatch(scan_type, target)
        except (UnknownScanTypeError, InvalidTargetError) as e:
            messages.error(request, str(e))
        else:
            messages.success(
                request,
                f"Scan {SCAN_LABELS[scan.scan_type]} #{scan.id} iniciado para {scan.target}.",
            )
            return redirect("scan_detail", scan_id=scan.id)

    scans = list(Scan.objects.all()[:HISTORY_LIMIT])
    has_active = any(s.status in ("RUNNING", "PENDING") for s in scans)
    return render(
        request,
        "scanners/dashboard.html",
        {
            "scans": scans,
            "has_active": has_active,
            "scan_types": SCAN_LABELS.items(),
            "form_scan_type": request.POST.get("scan_type", "nmap"),
            "form_target": request.POST.get("target", ""),
        },
    )


@login_required
def scan_detail(request, scan_id):
    """Detalhe de um scan: status, alvo, tempos e saída bruta."""
    scan = get_object_or_404(Scan, id=scan_id)
    return render(
        request,
        "scanners/scan_detail.html",
        {"scan": scan, "label": SCAN_LABELS.get(scan.scan_type, scan.scan_type)},
    )
