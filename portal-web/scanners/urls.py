from django.urls import path
from .views import TriggerScanView, ScanStatusView

urlpatterns = [
    path('start/', TriggerScanView.as_view(), name='start_scan'),
    path('<int:scan_id>/', ScanStatusView.as_view(), name='scan_status'),
]
