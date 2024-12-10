from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),  # Dashboard
    path('nmap/', views.nmap_scan, name='nmap_scan'), 
    path('whois/', views.whois_scan, name='whois_scan'),
    path('sublist3r/', views.sublist3r_scan, name='sublist3r_scan'),
    path('amass/', views.amass_scan_view, name='amass_scan'),
    path('zap/', views.zap_scan, name='zap_scan'),
    path('identify-ip-os/', views.ip_os_identification_view, name='identify_ip_os')
    

]
