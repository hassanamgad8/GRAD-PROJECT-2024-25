from django.shortcuts import render
from django.http import JsonResponse
from .models import ScanResult
import subprocess

def index(request):
    return render(request, 'tools/index.html')

def nmap_scan(request):
    if request.method == 'POST':
        target = request.POST.get('target')
        result = subprocess.getoutput(f'nmap {target}')
        ScanResult.objects.create(tool_name='Nmap', target=target, result=result)
        return JsonResponse({'result': result})
    return render(request, 'tools/modal_nmap.html')

def whois_scan(request):
    if request.method == 'POST':
        domain = request.POST.get('domain')
        result = subprocess.getoutput(f'whois {domain}')
        ScanResult.objects.create(tool_name='Whois', target=domain, result=result)
        return JsonResponse({'result': result})
    return render(request, 'tools/modal_whois.html')

def sublist3r_scan(request):
    if request.method == 'POST':
        domain = request.POST.get('domain')
        result = subprocess.getoutput(f'sublist3r -d {domain}')
        ScanResult.objects.create(tool_name='Sublist3r', target=domain, result=result)
        return JsonResponse({'result': result})
    return render(request, 'tools/modal_sublist3r.html')

def amass_scan(request):
    if request.method == 'POST':
        domain = request.POST.get('domain')
        result = subprocess.getoutput(f'amass enum -d {domain}')
        ScanResult.objects.create(tool_name='Amass', target=domain, result=result)
        return JsonResponse({'result': result})
    return render(request, 'tools/modal_amass.html')

def zap_scan(request):
    if request.method == 'POST':
        url = request.POST.get('url')
        result = subprocess.getoutput(f'zap-cli quick-scan {url}')
        ScanResult.objects.create(tool_name='OWASP ZAP', target=url, result=result)
        return JsonResponse({'result': result})
    return render(request, 'tools/modal_zap.html')
