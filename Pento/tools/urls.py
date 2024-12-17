from django.urls import path
from . import views


urlpatterns = [
    path('', views.login_view, name='login'),  # Root redirects to login page\
    path('login/', views.login_view, name='login'),
    path('dashboard/', views.dashboard_view, name='dashboard'),  # Add this for the dashboard
    path('nmap/', views.nmap_scan, name='nmap_scan'), 
    path('whois/', views.whois_scan, name='whois_scan'),
    path('sublist3r/', views.sublist3r_scan, name='sublist3r_scan'),
    path('amass/', views.amass_scan_view, name='amass_scan'),
    path('zap/', views.zap_scan_view, name='zap_scan'),
    path('dns_lookup/', views.dns_lookup, name='dns_lookup'),
    path('sqlmap/', views.sqlmap_scan_view, name='sqlmap_scan'),      
    path('xss/', views.xss_scan_view, name='xss_scan'), 
    path('nmap/progress/', views.nmap_scan_progress, name='nmap_scan_progress'),         
    
]
