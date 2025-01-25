import csv
from pyexpat.errors import messages
import queue
import re
import subprocess
from django.conf import settings
from django.urls import reverse
import whois
from .models import Report
from django.http import FileResponse, HttpResponseNotFound, HttpResponseRedirect, JsonResponse, StreamingHttpResponse
from django.http import HttpResponse
from django.shortcuts import redirect, render , get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from .models import Finding , Technology , Port , Host , Report , ScanConfig , ReportWebsiteScanner
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



from django.views.generic.base import TemplateView  # Added the correct import

class GoogleDorksView(TemplateView):
    template_name = 'google_hacking.html'  # Assuming your HTML file is named google_dorks.html
    
    def get(self, request, *args, **kwargs):
        return render(request, self.template_name)




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
import tempfile
import os



import os
import uuid
import logging
import threading
import subprocess
from urllib.parse import urlparse
from django.core.validators import URLValidator
from django.core.exceptions import ValidationError
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.http import JsonResponse
from django.conf import settings

def validate_target(target):
    try:
        response = subprocess.check_output(['curl', '-Is', target], stderr=subprocess.STDOUT, text=True)
        if '200 OK' not in response:
            return False
        return True
    except subprocess.CalledProcessError:
        return False
    

XSSSTRIKE_PATH = r'C:\Users\omarz\GRAD-PROJECT-2024-25\GRAD-PROJECT-2024-25\Pento\XSStrike\XSStrike.py'
SQLMAP_PATH = r'C:\Users\omarz\GRAD-PROJECT-2024-25\GRAD-PROJECT-2024-25\Pento\sqlmap-dev\sqlmap.py'    

def thread_run_scan(report_id):
    report = ReportWebsiteScanner.objects.get(id=report_id)

    try:
        report.status = "running"
        report.progress = 10
        report.save()

        # Use the new `run_scan` function
        scan_result = runn_scan(report_id, report.target)

        if scan_result["status"] == "completed":
            report.status = "completed"
            report.progress = 100
            report.result = scan_result["results"]
        else:
            report.status = "failed"
            report.result = "An error occurred during the scan."
        report.save()
    except Exception as e:
        report.status = "failed"
        report.result = f"Scan thread error: {e}"
        report.save()

def safe_subprocess_execute(command, timeout=300):
    try:
        result = subprocess.run(
            command, 
            capture_output=True, 
            text=True, 
            timeout=timeout,
            check=True
        )
        return {
            'status': 'success', 
            'output': result.stdout
        }
    except subprocess.CalledProcessError as e:
        return {
            'status': 'error', 
            'output': e.stderr
        }
    except FileNotFoundError:
        return {
            'status': 'not_found',
            'output': f"Executable not found: {command[0]}"
        }



def execute_tool_in_real_time(command, log_file_path=None):
    
    
    try:
        # Open the log file if provided
        log_file = open(log_file_path, 'w') if log_file_path else None

        # Execute the command
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        # Capture the output in real time
        for line in iter(process.stdout.readline, ''):
            print(line, end='')  # Print to console
            if log_file:
                log_file.write(line)  # Write to the log file
                log_file.flush()

        process.stdout.close()
        process.wait()

        # Check the exit code
        if process.returncode == 0:
            return {'status': 'success'}
        else:
            return {'status': 'error', 'error': f'Process exited with code {process.returncode}'}

    except Exception as e:
        return {'status': 'error', 'error': str(e)}
    finally:
        if log_file:
            log_file.close()


            
def perform_sql_injection_scan(target, sql_techniques='', waf_bypass=False, auto_detect_db=False, session_cookie=''):
    command = [
        'python', SQLMAP_PATH, '-u', target, '--batch',
        '--risk=3', '--level=5', '--forms', '--fresh-queries',
        '--timeout=600',  # Increased timeout
        '--crawl=2', '--crawl-depth=5', '--technique=BEUST'
    ]

    if sql_techniques:
        command.extend(['--technique', sql_techniques])
    if waf_bypass:
        command.extend(['--random-agent', '--tamper=space2comment'])
    if auto_detect_db:
        command.append('--dbms=auto')
    if session_cookie:
        command.extend(['--cookie', session_cookie])

    return execute_tool_in_real_time(command)

def perform_xss_scan(target, dom_xss=False, reflected_xss=False, stored_xss=False, xss_encoding='none', custom_scope='', payload_path=None):
    try:
        command = ['python', XSSSTRIKE_PATH, '-u', target]
        
        if dom_xss:
            command.append('--dom')
        if reflected_xss:
            command.append('--reflected')
        if stored_xss:
            command.append('--stored')
        if xss_encoding != 'none':
            command.extend(['--encode', xss_encoding])
        
        return safe_subprocess_execute(command)
    except Exception as e:
        return f"XSS Scan Error: {e}"

def runn_scan(report_id, target):
    # Create detailed logging
    log_dir = os.path.join(os.getcwd(), 'logs')
    os.makedirs(log_dir, exist_ok=True)
    log_file_path = os.path.join(log_dir, f"scan_{report_id}.log")

    logging.basicConfig(
        filename=log_file_path,
        level=logging.DEBUG,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )
    logger = logging.getLogger(__name__)

    try:
        logger.info(f"Starting scan for target: {target}")

        scan_results = {}

        # SQL Injection Scan
        try:
            logger.info("Starting SQL Injection scan")
            sql_result = perform_sql_injection_scan(target)
            scan_results["SQL Injection"] = sql_result
            logger.info(f"SQL Injection Scan Result: {sql_result}")
        except Exception as e:
            logger.error(f"SQL Injection scan failed: {e}")

        # XSS Scan
        try:
            logger.info("Starting XSS scan")
            xss_result = perform_xss_scan(target)
            scan_results["XSS Vulnerability"] = xss_result
            logger.info(f"XSS Scan Result: {xss_result}")
        except Exception as e:
            logger.error(f"XSS scan failed: {e}")

        # Add additional scans
        additional_scans = [
            ("SSL Certificate", check_ssl_certificate),
            ("HTTP Security Headers", check_http_security_headers),
            ("CMS Identification", identify_cms),
            ("Directory Indexing", check_directory_indexing),
            ("File Upload Vulnerability", check_file_upload_vulnerability),
            ("Backup Files", check_backup_files),
            ("CORS Misconfiguration", check_cors_misconfiguration),
        ]

        for scan_name, scan_function in additional_scans:
            try:
                logger.info(f"Starting {scan_name} scan")
                scan_result = scan_function(target)
                scan_results[scan_name] = scan_result
                logger.info(f"{scan_name} Scan Result: {scan_result}")
            except Exception as e:
                logger.error(f"{scan_name} scan failed: {e}")

        # Save final results
        combined_results = "\n".join([f"{key}: {value}" for key, value in scan_results.items()])
        with open(log_file_path, "w") as log_file:
            log_file.write(combined_results)

        return {
            "status": "completed",
            "progress": 100,
            "results": combined_results
        }
    except Exception as e:
        logger.critical(f"Scan failed: {e}")
        return {
            "status": "failed",
            "progress": 0,
            "results": str(e)
        }


@login_required
def website_scanner_view(request):
    if request.method == 'POST':
        target = request.POST.get('target')

        # Validate URL
        try:
            URLValidator()(target)
        except ValidationError:
            messages.error(request, "Invalid URL provided")
            return render(request, 'tools/website_scanner.html')

        # Create a report entry
        report = ReportWebsiteScanner.objects.create(
            target=target,
            scan_type='website_scanner',
            status='queued',
            progress=0,
            result="",
            created_by=request.user.username,
        )

        # Start the scan thread
        threading.Thread(target=thread_run_scan, args=(report.id,), daemon=True).start()

        # Redirect to the progress page
        return redirect('website_scanner_progress_page', scan_id=report.id)

    return render(request, 'tools/website_scanner.html')

@login_required
def website_scanner_progress_page(request, scan_id):
    try:
        report = get_object_or_404(ReportWebsiteScanner, id=scan_id, scan_type='website_scanner')
        return render(request, 'tools/website_scanner_progress.html', {'scan_id': scan_id, 'report': report})
    except Exception as e:
        print(f"Error: {e}")
        return render(request, 'tools/error.html', {'error': f"Report not found or invalid: {e}"})
    


@login_required
def website_scanner_progress(request, scan_id):
    try:
        report = ReportWebsiteScanner.objects.get(id=scan_id)
        log_dir = os.path.join(os.getcwd(), 'logs')
        log_file_path = os.path.join(log_dir, f'scan_{scan_id}.log')

        if os.path.exists(log_file_path):
            with open(log_file_path, 'r') as log_file:
                logs = log_file.read()
        else:
            logs = "Initializing scan...\n"

        return JsonResponse({
            'progress': report.progress,
            'status': report.status,
            'terminal_output': logs
        })
    except ReportWebsiteScanner.DoesNotExist:
        return JsonResponse({'error': 'Report not found'}, status=404)

def check_ssl_certificate(target):
    try:
        command = ['openssl', 's_client', '-connect', f"{target}:443", '-servername', target]
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, text=True)
        if 'Verify return code: 0 (ok)' in output:
            return "SSL/TLS certificate is valid."
        return "SSL/TLS certificate is invalid or expired."
    except subprocess.CalledProcessError as e:
        return f"Error: {e.output}"


def check_http_security_headers(target):
    try:
        command = ['curl', '-I', target]
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, text=True)
        headers = [
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-Content-Type-Options',
            'X-Frame-Options',
            'Referrer-Policy'
        ]
        missing_headers = [header for header in headers if header not in output]
        return f"Missing Headers: {', '.join(missing_headers)}" if missing_headers else "All important headers are present."
    except subprocess.CalledProcessError as e:
        return f"Error: {e.output}"


def identify_cms(target):
    try:
        command = ['whatweb', target]
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, text=True)
        if 'WordPress' in output:
            return "WordPress CMS detected."
        elif 'Joomla' in output:
            return "Joomla CMS detected."
        elif 'Drupal' in output:
            return "Drupal CMS detected."
        return "No CMS detected."
    except subprocess.CalledProcessError as e:
        return f"Error: {e.output}"
    except AttributeError:
        return "Error: Unable to parse CMS data."


def check_directory_indexing(target):
    try:
        command = ['curl', '-I', f"{target}/"]
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, text=True)
        if '200 OK' in output and '<title>Index of /</title>' in output:
            return "Directory indexing is enabled, which could expose sensitive files."
        return "Directory indexing is disabled."
    except subprocess.CalledProcessError as e:
        return f"Error: {e.output}"



def check_file_upload_vulnerability(target):
    try:
        # Write the test payload to a temporary file
        payload_file = os.path.join(tempfile.gettempdir(), 'test.php')
        with open(payload_file, 'w') as f:
            f.write('<?php echo "File uploaded successfully!"; ?>')

        command = ['curl', '-F', f'file=@{payload_file}', target]
        response = subprocess.check_output(command, stderr=subprocess.STDOUT, text=True)
        if 'File uploaded successfully!' in response:
            return "File upload vulnerability detected."
        return "No file upload vulnerability detected."
    except subprocess.CalledProcessError as e:
        return f"Error: {e.output}"


def check_backup_files(target):
    try:
        common_backup_files = ['backup.zip', 'backup.sql', 'db_backup.sql', '.env', 'config.php.bak']
        found_files = []
        for file in common_backup_files:
            command = ['curl', '-I', f"{target}/{file}"]
            response = subprocess.check_output(command, stderr=subprocess.STDOUT, text=True)
            if '200 OK' in response:
                found_files.append(file)
        return f"Found Backup Files: {', '.join(found_files)}" if found_files else "No backup files found."
    except subprocess.CalledProcessError as e:
        return f"Error: {e.output}"


def check_cors_misconfiguration(target):
    try:
        command = [
            'curl', '-I', '-H', 'Origin: http://evil.com', f"{target}"
        ]
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, text=True)
        if 'Access-Control-Allow-Origin: http://evil.com' in output:
            return "CORS misconfiguration detected. Cross-origin requests are allowed."
        return "No CORS misconfiguration detected."
    except subprocess.CalledProcessError as e:
        return f"Error: {e.output}"


def check_open_redirect(target):
    try:
        command = ['curl', '-I', f"{target}?redirect=https://evil.com"]
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, text=True)
        if 'evil.com' in output:
            return "Vulnerable to Open Redirect"
        return "Not Vulnerable"
    except subprocess.CalledProcessError as e:
        return f"Error: {e.output}"


def perform_directory_brute_force(target):
    try:
        common_dirs = ['admin', 'login', 'dashboard', 'config', 'backup']
        vulnerable_dirs = []
        for directory in common_dirs:
            command = ['curl', '-I', f"{target}/{directory}"]
            response = subprocess.check_output(command, stderr=subprocess.STDOUT, text=True)
            if '200 OK' in response:
                vulnerable_dirs.append(directory)
        return f"Vulnerable Directories: {', '.join(vulnerable_dirs)}" if vulnerable_dirs else "No vulnerable directories found."
    except subprocess.CalledProcessError as e:
        return f"Error: {e.output}"



def check_outdated_software(target):
    try:
        command = ['whatweb', target]
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, text=True)
        return output
    except subprocess.CalledProcessError as e:
        return f"Error: {e.output}"


    
def export_report(request, report_id):
    report = get_object_or_404(ReportWebsiteScanner, id=report_id)
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

def cleanup_logs(scan_id):
    log_file_path = f"/tmp/scan_{scan_id}.log"
    if os.path.exists(log_file_path):
        os.remove(log_file_path)






@login_required
def website_scanner_results_page(request, scan_id):
    report = get_object_or_404(ReportWebsiteScanner, id=scan_id, scan_type='website_scanner')

    context = {
        'report': report,
        'raw_results': report.result,
        'results': [],
        'error': None
    }

    try:
        if report.status == 'completed' and report.result:
            parsed_results = parse_website_scan_results(report.result)
            context['results'] = parsed_results
        elif report.status == 'failed':
            context['error'] = "Scan failed. Check raw results for details."
        elif report.status != 'completed':
            context['error'] = f"Scan status: {report.status}"
    except Exception as e:
        context['error'] = f"Error processing results: {str(e)}"
        logging.error(f"Error in website_scanner_results_page: {str(e)}")

    return render(request, 'tools/website_scanner_results.html', context)



def parse_website_scan_results(result_data):
    """
    Parse Website Scanner results, including additional features.
    """
    if not result_data:
        return []

    parsed_results = []

    try:
        lines = result_data.splitlines()
        for line in lines:
            line = line.strip()

            # Parse XSS findings
            if "XSS Vulnerability Found:" in line:
                parsed_results.append({
                    'type': 'XSS',
                    'description': line.split("XSS Vulnerability Found: ")[-1],
                })

            # Parse SQL Injection findings
            elif "SQL Injection Vulnerability Found:" in line:
                parsed_results.append({
                    'type': 'SQL Injection',
                    'description': line.split("SQL Injection Vulnerability Found: ")[-1],
                })

            # Parse Open Redirect findings
            elif "Open Redirect Found:" in line:
                parsed_results.append({
                    'type': 'Open Redirect',
                    'description': line.split("Open Redirect Found: ")[-1],
                })

            # Parse Directory Brute Force findings
            elif "Directory Brute Force Result:" in line:
                parsed_results.append({
                    'type': 'Directory Brute Force',
                    'description': line.split("Directory Brute Force Result: ")[-1],
                })

            # Parse Outdated Software findings
            elif "Outdated Software Detected:" in line:
                parsed_results.append({
                    'type': 'Outdated Software',
                    'description': line.split("Outdated Software Detected: ")[-1],
                })

            # Parse SSL/TLS Certificate findings
            elif "SSL Certificate Check:" in line:
                parsed_results.append({
                    'type': 'SSL/TLS Certificate',
                    'description': line.split("SSL Certificate Check: ")[-1],
                })

            # Parse HTTP Security Headers findings
            elif "Missing Security Header:" in line:
                parsed_results.append({
                    'type': 'HTTP Security Header',
                    'description': line.split("Missing Security Header: ")[-1],
                })

            # Parse CMS Identification findings
            elif "CMS Identified:" in line:
                parsed_results.append({
                    'type': 'CMS Identification',
                    'description': line.split("CMS Identified: ")[-1],
                })

            # Parse Directory Indexing findings
            elif "Directory Indexing Found:" in line:
                parsed_results.append({
                    'type': 'Directory Indexing',
                    'description': line.split("Directory Indexing Found: ")[-1],
                })

            # Parse File Upload Vulnerability findings
            elif "File Upload Vulnerability Found:" in line:
                parsed_results.append({
                    'type': 'File Upload Vulnerability',
                    'description': line.split("File Upload Vulnerability Found: ")[-1],
                })

            # Parse Backup Files findings
            elif "Backup File Found:" in line:
                parsed_results.append({
                    'type': 'Backup File',
                    'description': line.split("Backup File Found: ")[-1],
                })

            # Parse CORS Misconfiguration findings
            elif "CORS Misconfiguration Found:" in line:
                parsed_results.append({
                    'type': 'CORS Misconfiguration',
                    'description': line.split("CORS Misconfiguration Found: ")[-1],
                })

    except Exception as e:
        logging.error(f"Error parsing Website Scanner results: {str(e)}")
        return [{'error': f'Error parsing results: {str(e)}'}]

    return parsed_results






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