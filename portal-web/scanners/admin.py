from django.contrib import admin
from .models import Scan
from .tasks import run_nmap_scan, run_gobuster_scan, run_nuclei_scan, run_masscan_scan

SCAN_DISPATCH = {
    'nmap': run_nmap_scan,
    'gobuster': run_gobuster_scan,
    'nuclei': run_nuclei_scan,
    'masscan': run_masscan_scan,
}


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ('id', 'scan_type', 'target', 'status', 'created_at', 'finished_at')
    list_filter = ('status', 'scan_type')
    search_fields = ('target',)
    readonly_fields = ('status', 'task_id', 'output', 'created_at', 'finished_at')

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        if not change:  # Dispara a varredura apenas na criação de um novo registro.
            task = SCAN_DISPATCH.get(obj.scan_type)
            if task:
                task.delay(obj.id)
