import csv
import re
import subprocess
from django.urls import reverse
import whois
from .models import Report
from django.http import FileResponse, HttpResponseNotFound, HttpResponseRedirect, JsonResponse, StreamingHttpResponse
from django.http import HttpResponse
from django.shortcuts import redirect, render , get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from .models import Finding , Technology , Port , Host , Report , ScanConfig
import dns.resolver
import sublist3r
import socket
import threading
from django.core.cache import cache
import uuid
import json
import logging
from zapv2 import ZAPv2
import time
import tempfile
from django.views.decorators.csrf import csrf_protect
from datetime import datetime
from django.shortcuts import get_object_or_404
import os
from django.core.paginator import Paginator






logger = logging.getLogger(__name__)

def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('dashboard')
        else:
            return render(request, 'tools/login.html', {'error_message': 'Invalid login'})
    return render(request, 'tools/login.html')

@login_required
def dashboard_view(request):
    # Fetch tools and reports for the dashboard
    tools = {
        'port_scanner': 'Port Scanner',
        'whois': 'Whois',
        'domain_finder': 'Domain Finder',
        'subdomain_finder': 'Subdomain Finder',
        'zap': 'ZAP',
        'website_scanner': 'Website Scanner'
    }
    # Order by 'created_at' instead of 'timestamp'
    reports = Report.objects.all().order_by('-created_at')[:10]  # Fetch the latest 10 reports

    # Active scans data
    active_scans = {
        'running': Report.objects.filter(status='running').count(),
        'queued': Report.objects.filter(status='queued').count(),
        'completed': Report.objects.filter(status='completed').count(),
    }

    # Pass the data to the template
    context = {
        'tools': tools,
        'reports': reports,
        'active_scans': active_scans,
    }
    return render(request, 'tools/dashboard.html', context)

def logout_view(request):
    if request.method == 'POST':
        logout(request)
        return HttpResponseRedirect(reverse('login'))
    return HttpResponse(status=405)

@login_required
def reports_view(request):
    # Apply filters if any
    scan_type = request.GET.get('scan_type', '')
    reports = Report.objects.all().order_by('-timestamp')
    if scan_type:
        reports = reports.filter(scan_type=scan_type)

    # Paginate reports
    paginator = Paginator(reports, 10)  # Show 10 reports per page
    page_number = request.GET.get('page')
    page_reports = paginator.get_page(page_number)

    return render(request, 'tools/reports.html', {'reports': page_reports})

def report_detail_view(request, report_id):
    report = get_object_or_404(Report, id=report_id)
    return JsonResponse({'scan_type': report.scan_type, 'target': report.target, 'result': report.result})

def download_report(request, report_name):
    file_path = fr'C:\Users\omarz\GRAD-PROJECT-2024-25\GRAD-PROJECT-2024-25\Pento\reports{report_name}'
    if os.path.exists(file_path):
        return FileResponse(open(file_path, 'rb'), as_attachment=True, filename=report_name)
    else:
        return HttpResponseNotFound("File not found.")


def api_attack_surface(request):
    hosts = Host.objects.all()
    data = [
        {
            "hostname": host.hostname,
            "ip_address": host.ip_address,
            "os": "Unknown",  # Update with actual data if available
            "port": ", ".join([f"{port.port_number}/{port.protocol}" for port in host.ports.all()]),
            "protocol": "Unknown",  # Update with actual data if available
            "service": ", ".join([port.service for port in host.ports.all() if port.service]),
            "url": "Unknown",  # Update with actual data if available
            "technology": ", ".join([tech.name for tech in host.technologies.all()]),
            "screenshot": "-",  # Update with actual data if available
        }
        for host in hosts
    ]
    return JsonResponse(data, safe=False)

def dashboard_summary(request):
    data = {
        "ip_address_count": 1,
        "hostnames_count": 2,
        "port_count": 1,
        "protocol_count": 1,
        "services_count": 0,
        "technologies_count": 22,
    }
    return JsonResponse(data)


def api_assets(request):
    hosts = Host.objects.all()
    data = [
        {
            "hostname": host.hostname,
            "ip_address": host.ip_address,
            "port_number": Port.port_number if host.ports.exists() else None,
            "protocol": Port.protocol if host.ports.exists() else None,
            "service": Port.service if host.ports.exists() else None,
            "technology": [tech.name for tech in host.technologies.all()]
        }
        for host in hosts
    ]
    return JsonResponse(data, safe=False)

def api_findings(request):
    findings = Finding.objects.all()
    data = [
        {
            "description": finding.description,
            "target": finding.target,
            "status": finding.status,
            "risk_level": finding.risk_level,
            "source": finding.source,
            "scan_date": finding.scan_date.strftime("%Y-%m-%d %H:%M:%S"),
        }
        for finding in findings
    ]
    return JsonResponse(data, safe=False)


def whois_view(request):
    if request.method == "POST":
        domain = request.POST.get('domain')
        options = {
            'reverse_whois': request.POST.get('reverse_whois'),
            'dns_records': request.POST.get('dns_records'),
            'historical_records': request.POST.get('historical_records'),
            'geo_location': request.POST.get('geo_location'),
            'domain_age': request.POST.get('domain_age'),
            'explain_status': request.POST.get('explain_status'),
            'output_format': request.POST.get('output_format', 'plain'),
        }

        response_data = {}
        # Include selected options in response
        response_data['selected_options'] = {key: 'Yes' if value == 'on' else 'No' for key, value in options.items()}

        try:
            # Basic Whois Lookup
            whois_info = whois.whois(domain)
            response_data['whois'] = whois_info.text

            # Reverse Whois (Placeholder - requires external API or service)
            if options['reverse_whois']:
                response_data['reverse_whois'] = "Reverse Whois Lookup not implemented."

            # DNS Records
            if options['dns_records']:
                dns_records = {}
                for record_type in ['A', 'MX', 'NS', 'TXT']:
                    try:
                        if record_type == 'A':
                            dns_records[record_type] = socket.gethostbyname(domain)
                        else:
                            dns_records[record_type] = [rdata.to_text() for rdata in dns.resolver.resolve(domain, record_type)]
                    except Exception as e:
                        dns_records[record_type] = str(e)
                response_data['dns_records'] = dns_records

            # Domain Age
            if options['domain_age']:
                creation_date = whois_info.creation_date
                if creation_date:
                    domain_age = (datetime.datetime.now() - creation_date).days
                    response_data['domain_age'] = f"{domain_age} days"
                else:
                    response_data['domain_age'] = "Creation date not available."

            # Domain Status Explanation
            if options['explain_status']:
                response_data['status_explanation'] = explain_status_codes(whois_info.status)

            # Formatting Output
            if options['output_format'] == 'json':
                return JsonResponse(response_data)
            elif options['output_format'] == 'xml':
                # Convert response_data to XML format
                response_data['xml'] = "XML Formatting not implemented."
            else:
                # Plain text output
                plain_text_output = "Selected Options:\n"
                for option, value in response_data['selected_options'].items():
                    plain_text_output += f"{option}: {value}\n"
                plain_text_output += "\nWhois Data:\n"
                plain_text_output += response_data['whois']
                response_data['plain_text'] = plain_text_output

        except Exception as e:
            response_data['error'] = str(e)

        return render(request, 'modal_whois.html', {'response_data': response_data})

    return render(request, 'modal_whois.html')

def explain_status_codes(status_codes):
    status_explanations = {
        "clientTransferProhibited": "The domain cannot be transferred to another registrar.",
        "clientDeleteProhibited": "The domain cannot be deleted.",
        "clientUpdateProhibited": "The domain cannot be updated.",
    }
    explanations = {}
    if status_codes:
        for code in status_codes:
            explanations[code] = status_explanations.get(code, "Explanation not available.")
    return explanations



def dns_lookup(request):
    if request.method == 'POST':
        domain = request.POST.get('domain')
        if not domain:
            return JsonResponse({'error': 'No domain provided'}, status=400)
        try:
            records = dns.resolver.resolve(domain, 'A')
            results = [str(record) for record in records]
            # Save the report
            Report.objects.create(scan_type='DNS Lookup', target=domain, result='\n'.join(results))
            return JsonResponse({'data': results})
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    return render(request, 'tools/modal_dns_lookup.html')



logger = logging.getLogger(__name__)



@login_required
def nmap_scan(request):
    if request.method == 'POST':
        # Extract form data
        target = request.POST.get('target')
        enable_ping = request.POST.get('enable_ping')
        port_scan = request.POST.get('port_scan')
        scan_technique = request.POST.get('scan_technique')
        enable_version = request.POST.get('enable_version')
        timing_template = request.POST.get('timing_template')
        decoys = request.POST.get('decoys')
        custom_ports = request.POST.get('custom_ports')
        nmap_scripts = request.POST.get('nmap_scripts')

        # Validate target input
        if not target or not re.match(r'^[\w\-\.\:\/]+$', target):
            return JsonResponse({'error': 'Invalid target specified'}, status=400)

        # Create a new Report instance first
        report = Report.objects.create(
            scan_type='port_scanner',
            target=target,
            status='queued',
            progress=0,
            created_by=request.user.username,
        )

        # Create base command with proper flags
        command = ['nmap', '-oN']
        
        # Define the reports directory and output file path
        reports_dir = os.path.join(os.path.dirname(__file__), 'reports')
        os.makedirs(reports_dir, exist_ok=True)
        output_file = f'output_{report.id}.txt'  # Now report.id is defined
        output_path = os.path.join(reports_dir, output_file)
        command.append(output_path)

        # Add ping option
        if enable_ping == 'no-ping':
            command.append('-Pn')
        elif enable_ping == 'ping-only':
            command.append('-sn')

        # Add port scan type
        if port_scan == 'quick':
            command.append('-F')
        elif port_scan == 'full':
            command.append('-p-')

        # Add scan technique
        if scan_technique:
            scan_flags = {
                'syn': '-sS',
                'tcp': '-sT',
                'udp': '-sU',
                'ack': '-sA'
            }
            if scan_technique in scan_flags:
                command.append(scan_flags[scan_technique])

        # Version detection
        if enable_version == 'on':
            command.append('-sV')

        # Timing template
        if timing_template:
            if timing_template in ['T0', 'T1', 'T2', 'T3', 'T4', 'T5']:
                command.append(f'-{timing_template}')

        # Add decoys
        if decoys:
            # Split and validate decoy IPs
            decoy_list = [d.strip() for d in decoys.split(',')]
            valid_decoys = []
            for decoy in decoy_list:
                if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', decoy):
                    valid_decoys.append(decoy)
            if valid_decoys:
                command.append('-D')
                command.append(','.join(valid_decoys))

        # Add custom ports
        if custom_ports:
            if re.match(r'^[\d,\-]+$', custom_ports):
                command.extend(['-p', custom_ports])

        # Add NSE scripts
        if nmap_scripts:
            safe_scripts = ['default', 'discovery', 'safe', 'auth', 'vuln']
            if nmap_scripts in safe_scripts:
                command.extend(['--script', nmap_scripts])

        # Add verbosity for better progress tracking
        command.append('-v')

        # Add target last
        command.append(target)

        # Define run_scan function with proper report access
        def run_scan(report_id):
            try:
                report = Report.objects.get(id=report_id)
                report.status = 'running'
                report.save()

                # Log the command being executed
                logging.info(f"Executing Nmap command: {' '.join(command)}")

                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                    universal_newlines=True
                )

                output_buffer = []
                with open(output_path, 'w') as f:
                    while True:
                        output = process.stdout.readline()
                        if output == '' and process.poll() is not None:
                            break
                        if output:
                            output_buffer.append(output)
                            f.write(output)
                            f.flush()
                            
                            # More detailed progress tracking
                            if "Starting Nmap" in output:
                                report.progress = 5
                            elif "Initiating" in output:
                                report.progress = 10
                            elif "Scanning" in output:
                                report.progress = 30
                            elif "Discovered open port" in output:
                                report.progress = min(report.progress + 5, 90)
                            elif "NSE: Script scanning" in output:
                                report.progress = 70
                            elif "Nmap scan report for" in output:
                                report.progress = 95
                            elif "Nmap done" in output:
                                report.progress = 100
                            report.save()

                # Wait for process to complete
                process.wait()

                # Get complete output
                stderr = process.stderr.read()
                
                # Combine all output
                complete_output = ''.join(output_buffer)
                if stderr:
                    complete_output += f"\nErrors:\n{stderr}"

                report.result = complete_output
                
                if process.returncode == 0:
                    report.status = 'completed'
                else:
                    report.status = 'failed'
                    logging.error(f"Nmap scan failed with return code {process.returncode}")
                    
                report.save()

            except Exception as e:
                logging.error(f"Error during scan: {str(e)}")
                report.status = 'failed'
                report.result = f"Error during scan: {str(e)}"
                report.save()

        # Start the scan
        thread = threading.Thread(target=run_scan, args=(report.id,))  # Now report.id is defined
        thread.daemon = True
        thread.start()

        return HttpResponseRedirect(reverse('progress_page', args=[report.id]))  # Now report.id is defined

    return render(request, 'tools/modal_nmap.html')

@login_required
def scan_progress(request, scan_id):
    try:
        # Fetch the report by scan_id
        report = Report.objects.get(id=scan_id, scan_type='port_scanner')
    except Report.DoesNotExist:
        return JsonResponse({'error': 'Invalid scan ID'}, status=400)

    # Check the scan status and fetch terminal output if available
    terminal_output = ""
    if report.status in ['running', 'completed']:
        reports_dir = os.path.join(os.path.dirname(__file__), 'reports')
        output_path = os.path.join(reports_dir, f'output_{scan_id}.txt')
        if os.path.exists(output_path):
            with open(output_path, 'r') as f:
                terminal_output = f.read()

    # Return progress, status, and output
    return JsonResponse({
        'progress': report.progress,
        'status': report.status,
        'terminal_output': terminal_output
    })

@login_required
def progress_page(request, scan_id):
    # Fetch the scan details to pass to the template
    report = get_object_or_404(Report, id=scan_id)
    return render(request, 'progress.html', {'scan_id': scan_id, 'report': report})

def results_page(request, scan_id):
    report = get_object_or_404(Report, id=scan_id)
    
    context = {
        'report': report,
        'raw_results': report.result,
        'results': [],
        'error': None
    }

    try:
        if report.status == 'completed' and report.result:
            parsed_results = parse_scan_results(report.result)
            context['results'] = parsed_results
        elif report.status == 'failed':
            context['error'] = "Scan failed. Check raw results for details."
        elif report.status != 'completed':
            context['error'] = f"Scan status: {report.status}"
    except Exception as e:
        context['error'] = f"Error processing results: {str(e)}"
        logging.error(f"Error in results_page: {str(e)}")

    return render(request, 'tools/results.html', context)

def parse_scan_results(result_data):
    """
    Parse Nmap scan results into a structured format.
    """
    if not result_data:
        return []

    parsed_results = []
    current_port = None
    current_host = None
    
    try:
        lines = result_data.splitlines()
        for line in lines:
            line = line.strip()
            
            # Parse host information
            if "Nmap scan report for" in line:
                current_host = line.split("Nmap scan report for ")[-1]
                continue
                
            # Parse port information
            port_match = re.search(r'(\d+)\/(\w+)\s+(\w+)\s+(.+)', line)
            if port_match:
                current_port = {
                    'port': port_match.group(1),
                    'protocol': port_match.group(2),
                    'state': port_match.group(3),
                    'service': port_match.group(4),
                    'host': current_host,
                    'details': []
                }
                parsed_results.append(current_port)
                continue
                
            # Parse service details
            if current_port and line.startswith('|'):
                current_port['details'].append(line.strip('| '))
                
            # Parse service version
            version_match = re.search(r'Service Info: (.*)', line)
            if version_match and current_port:
                current_port['version'] = version_match.group(1)

    except Exception as e:
        logging.error(f"Error parsing Nmap results: {str(e)}")
        return [{'error': f'Error parsing results: {str(e)}'}]

    return parsed_results




import sys

# Sublist3r
def sublist3r_scan(request):
    if request.method == 'POST':
        # Extract options from the request
        domain = request.POST.get('domain')
        thread_count = request.POST.get('thread_count', 10)  # Default to 10 threads
        enable_bruteforce = request.POST.get('brute_force') == 'true'

        try:
            # Prepare a temporary file to save the results
            with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as temp_file:
                savefile = temp_file.name

            # Command to run Sublist3r
            command = [
                sys.executable, '-m', 'sublist3r',
                '-d', domain,
                '-o', savefile,
                '-t', str(thread_count)
            ]

            # Add brute force option if enabled
            if enable_bruteforce:
                command.append('-b')

            # Run the Sublist3r command
            subprocess.run(command, check=True, text=True)

            # Read results from the saved file
            with open(savefile, 'r') as result_file:
                subdomains = result_file.read().splitlines()

            # Save the results to the database
            Report.objects.create(
                scan_type='Sublist3r',
                target=domain,
                result="\n".join(subdomains)
            )

            return JsonResponse({'result': subdomains})

        except subprocess.CalledProcessError as e:
            return JsonResponse({'error': f'Sublist3r execution failed: {str(e)}'}, status=500)

    return render(request, 'tools/modal_sublist3r.html')



logger = logging.getLogger(__name__)



def website_scanner_view(request):
    if request.method == 'POST':
        # General Input
        target = request.POST.get('target')
        include_subdomains = request.POST.get('include_subdomains') == 'true'
        custom_scope = request.POST.get('custom_scope', '')
        file_types = request.POST.get('file_types', '')

        # Authentication
        username = request.POST.get('username', '')
        password = request.POST.get('password', '')
        session_cookie = request.POST.get('session_cookie', '')
        auth_token = request.POST.get('auth_token', '')

        # Scanning Modes
        scan_mode = request.POST.get('scan_mode', 'full')

        # Advanced SQL Options
        waf_bypass = request.POST.get('waf_bypass') == 'true'
        sql_techniques = request.POST.get('sql_techniques', '')
        auto_detect_db = request.POST.get('auto_detect_db') == 'true'

        # Advanced XSS Options
        reflected_xss = request.POST.get('reflected_xss') == 'true'
        stored_xss = request.POST.get('stored_xss') == 'true'
        dom_xss = request.POST.get('dom_xss') == 'true'
        xss_encoding = request.POST.get('xss_encoding', 'none')
        custom_payloads = request.FILES.get('custom_payloads')

        # Save custom payload file if provided
        payload_path = None
        if custom_payloads:
            payload_path = f"/tmp/{custom_payloads.name}"
            with open(payload_path, 'wb') as f:
                for chunk in custom_payloads.chunks():
                    f.write(chunk)

        # Execute scans based on the selected mode
        results = {}
        if scan_mode in ['full', 'sql']:
            results['sql'] = perform_sql_injection_scan(
                target, sql_techniques, waf_bypass, auto_detect_db, session_cookie
            )

        if scan_mode in ['full', 'xss']:
            results['xss'] = perform_xss_scan(
                target, dom_xss, reflected_xss, stored_xss, xss_encoding, custom_scope, payload_path
            )

        # Combine results
        combined_results = "\n\n".join([f"{key.upper()}:\n{value}" for key, value in results.items()])

        # Save the report to the database
        report = Report.objects.create(target=target, result=combined_results)

        return JsonResponse({'results': results})

    return render(request, 'tools/website_scanner.html')



def perform_sql_injection_scan(target, sql_techniques, waf_bypass, auto_detect_db, session_cookie):
    try:
        command = [
            'sqlmap', '-u', target, '--batch', '--forms', '--flush-session', '--fresh-queries',
            '--crawl=2', '--crawl-depth=5', '--level=5', '--risk=3', '--technique=BEUST'
        ]

        # Add WAF bypass
        if waf_bypass:
            command.extend(['--random-agent', '--tamper=space2comment'])

        # Add database auto-detection
        if auto_detect_db:
            command.append('--dbms=auto')

        # Add session cookie
        if session_cookie:
            command.extend(['--cookie', session_cookie])

        # Execute the command
        return subprocess.check_output(command, stderr=subprocess.STDOUT, text=True)

    except subprocess.CalledProcessError as e:
        return f"Error: {e.output}"

    
def perform_xss_scan(target, dom_xss, reflected_xss, stored_xss, xss_encoding, custom_scope, payload_path):
    try:
        command = ['xsstrike', '-u', target]

        # Add DOM-based XSS testing
        if dom_xss:
            command.append('--dom')

        # Add Reflected XSS testing
        if reflected_xss:
            command.append('--reflected')

        # Add Stored XSS testing
        if stored_xss:
            command.append('--stored')

        # Add encoding
        if xss_encoding != 'none':
            command.extend(['--encode', xss_encoding])

        # Add custom scope
        if custom_scope:
            command.extend(['--regex', custom_scope])

        # Add custom payloads
        if payload_path:
            command.extend(['--payload', payload_path])

        # Validate target
        response = subprocess.check_output(['curl', '-Is', target], stderr=subprocess.STDOUT, text=True)
        if '200 OK' not in response:
            return "Target is unreachable."

        # Execute command
        return subprocess.check_output(command, stderr=subprocess.STDOUT, text=True)

    except subprocess.CalledProcessError as e:
        return f"Error: {e.output}"



    

    
def export_report(request, report_id):
    report = get_object_or_404(Report, id=report_id)
    export_format = request.GET.get('format', 'html')

    if export_format == 'json':
        response = JsonResponse({'results': report.result})
        response['Content-Disposition'] = f'attachment; filename="{report.target}_results.json"'
    elif export_format == 'csv':
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="{report.target}_results.csv"'
        writer = csv.writer(response)
        for line in report.result.splitlines():
            writer.writerow([line])
    else:  # Default to HTML
        response = HttpResponse(report.result, content_type='text/html')
        response['Content-Disposition'] = f'attachment; filename="{report.target}_results.html"'

    return response

def website_scanner_progress(request):
    """
    Simulated progress of the website scanner.
    Replace this with actual logic to stream real-time progress if needed.
    """
    progress_messages = [
        {"message": "Initializing scan..."},
        {"message": "Checking for XSS vulnerabilities..."},
        {"message": "Performing SQL injection tests..."},
        {"message": "Finalizing report..."},
        {"message": "Scan completed successfully."},
    ]
    return JsonResponse({"messages": progress_messages})




# OWASP ZAP Scanner
def zap_scan_view(request):
    if request.method == 'POST':
        target_url = request.POST.get('target_url')
        if not target_url:
            return JsonResponse({'error': 'Target URL is required.'}, status=400)
        
        zap = ZAPv2(apikey='your_api_key', proxies={'http': 'http://localhost:8080', 'https': 'http://localhost:8080'})
        try:
            # Spider the target
            zap.spider.scan(target_url)
            while int(zap.spider.status) < 100:
                time.sleep(1)

            # Active scan
            zap.ascan.scan(target_url)
            while int(zap.ascan.status) < 100:
                time.sleep(1)

            alerts = zap.core.alerts(baseurl=target_url)
            # Save the report
            Report.objects.create(scan_type='ZAP', target=target_url, result=str(alerts))
            return JsonResponse({'alerts': alerts})
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    return render(request, 'tools/modal_zap.html')


def dns_lookup(request):
    if request.method == 'POST':
        domain = request.POST.get('domain')  # Get the domain from the form input
        if not domain:
            return JsonResponse({'error': 'No domain provided'}, status=400)

        try:
            # Perform DNS A record lookup
            records = dns.resolver.resolve(domain, 'A')
            results = [str(record) for record in records]
            return JsonResponse({'data': results})  # Return the results as JSON
        except dns.resolver.NXDOMAIN:
            return JsonResponse({'error': 'Domain does not exist'}, status=404)
        except dns.resolver.Timeout:
            return JsonResponse({'error': 'DNS query timed out'}, status=500)
        except dns.resolver.NoAnswer:
            return JsonResponse({'error': 'No answer received for the query'}, status=500)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return render(request, 'tools/modal_dns_lookup.html')  # Render the form for DNS Lookup



def is_valid_domain(domain):
    """
    Validate the domain format using regex.
    """
    regex = r'^(?!:\/\/)([a-zA-Z0-9-_]+\.)+[a-zA-Z]{2,6}$'
    return re.match(regex, domain) is not None

def amass_scan_view(request):
    if request.method == 'POST':
        domain = request.POST.get('domain')

        # Validate domain input
        if not domain:
            return JsonResponse({'error': 'Domain is required'}, status=400)

        options = []

        # Handle general options
        if request.POST.get('passive') == 'true':
            options.append('-passive')
        if request.POST.get('active') == 'true':
            options.append('-active')
        if request.POST.get('dns_brute') == 'true':
            options.append('-brute')  # Brute-forcing subdomains

        # Add valid options for DNS and IP
        if request.POST.get('ip_addresses') == 'true':
            options.append('-ip')  # Map subdomains to IPs
        if request.POST.get('asn_mapping') == 'true':
            options.append('-asn')  # Map subdomains to ASN and CIDR

        # Construct the command
        command = ['amass', 'enum', '-d', domain] + options

        try:
            # Execute the command
            result = subprocess.check_output(command, stderr=subprocess.STDOUT, text=True)
            
            # Save the result in the database
            Report.objects.create(scan_type='Amass', target=domain, result=result)
            
            return JsonResponse({'result': result})
        except subprocess.CalledProcessError as e:
            # Return detailed error output for debugging
            return JsonResponse({'error': f"Amass error: {e.output}"}, status=500)
        except FileNotFoundError:
            # Handle case where amass is not installed or not found
            return JsonResponse({'error': 'Amass is not installed on the server'}, status=500)
        except Exception as e:
            # Handle other unexpected errors
            return JsonResponse({'error': str(e)}, status=500)

    # Render the form for GET requests
    return render(request, 'tools/modal_amass.html')




def save_scan_results(target, findings, ports, technologies):
    """
    Save scan results into the database for Findings, Ports, and Technologies.
    """
    # Save the host
    host, created = Host.objects.get_or_create(
        hostname=target["hostname"],
        ip_address=target["ip_address"],
    )

    # Save ports
    for port in ports:
        Port.objects.get_or_create(
            port_number=port["port_number"],
            protocol=port["protocol"],
            service=port.get("service", ""),
            host=host,
        )

    # Save technologies
    for tech in technologies:
        Technology.objects.get_or_create(
            name=tech["name"],
            version=tech.get("version", ""),
            host=host,
        )

    # Save findings
    for finding in findings:
        Finding.objects.create(
            description=finding["description"],
            target=host,
            risk_level=finding["risk_level"],
            source=finding["source"],
        )

def perform_scan(request):
    """
    Perform a scan and save the results to the database.
    """
    if request.method == "POST":
        target = request.POST.get("target")
        if not target:
            return JsonResponse({"error": "Target is required"}, status=400)

        # Simulated scan results
        scan_data = {
            "target": {"hostname": "example.com", "ip_address": "192.168.1.1"},
            "ports": [
                {"port_number": 80, "protocol": "tcp", "service": "HTTP"},
                {"port_number": 443, "protocol": "tcp", "service": "HTTPS"},
            ],
            "technologies": [
                {"name": "Apache", "version": "2.4.41"},
                {"name": "PHP", "version": "7.4.3"},
            ],
            "findings": [
                {
                    "description": "Insecure cookie setting: missing Secure flag",
                    "risk_level": "medium",
                    "source": "Website Scanner",
                },
                {
                    "description": "Missing security header: Strict-Transport-Security",
                    "risk_level": "low",
                    "source": "Website Scanner",
                },
            ],
        }

        # Save results to the database
        save_scan_results(
            target=scan_data["target"],
            findings=scan_data["findings"],
            ports=scan_data["ports"],
            technologies=scan_data["technologies"],
        )

        return JsonResponse({"message": "Scan completed and results saved."})
    return JsonResponse({"error": "Invalid request method"}, status=405)