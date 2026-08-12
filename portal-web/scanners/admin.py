from django.contrib import admin
from .models import Scan
from .tasks import run_nmap_scan

@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ('id', 'target', 'status', 'created_at')
    list_filter = ('status',)
    search_fields = ('target',)
    readonly_fields = ('status', 'output', 'created_at')

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        if not change:  # Se for a criação de um novo registro
            run_nmap_scan.delay(obj.id)