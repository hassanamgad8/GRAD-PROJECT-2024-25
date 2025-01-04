from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

urlpatterns = [
    path('', views.login_view, name='login'),
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('logout/', views.logout_view, name='logout'),
    path('port_scanner/', views.nmap_scan, name='port_scanner'),
    path('scan_progress/<int:scan_id>/', views.scan_progress, name='scan_progress'),
    path('scan_result/<int:scan_id>/', views.scan_result, name='scan_result'),
    path('whois/', views.whois_view, name='whois'),
    path('domain_finder/', views.amass_scan_view, name='domain_finder'),
    path('subdomain_finder/', views.sublist3r_scan, name='subdomain_finder'),
    path('dns_lookup/', views.dns_lookup, name='dns_lookup'),
    path('zap/', views.zap_scan_view, name='zap'),
    path('website_scanner/', views.website_scanner_view, name='website_scanner'),
    path('website_scanner_progress/', views.website_scanner_progress, name='website_scanner_progress'),
    path('reports/', views.reports_view, name='reports'),
    path('reports/<int:report_id>/', views.report_detail_view, name='report_detail'),
    path('download/<str:report_name>/', views.download_report, name='download_report'),
    path("api/attack-surface/", views.api_attack_surface, name="api_attack_surface"),
    path("api/dashboard-summary/", views.dashboard_summary, name="dashboard_summary"),
     path("api/assets/", views.api_assets, name="assets-api"),
    path("api/findings/", views.api_findings, name="findings-api"),
    path("scan/", views.perform_scan, name="perform_scan"),
    
]
     
    
    