from django.contrib import admin
from .models import Scan

@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ('target', 'status', 'created_at')
    list_filter = ('status',)
    search_fields = ('target',)
