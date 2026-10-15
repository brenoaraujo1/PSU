from django.urls import path
from .views import TriggerScanView

urlpatterns = [
    path('start/', TriggerScanView.as_view(), name='start_scan'),
]