from django.urls import path

from .web_views import dashboard, scan_detail

urlpatterns = [
    path('', dashboard, name='dashboard'),
    path('scan/<int:scan_id>/', scan_detail, name='scan_detail'),
]
