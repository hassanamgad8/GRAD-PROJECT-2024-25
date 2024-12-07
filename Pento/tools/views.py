import subprocess
import whois
from django.http import JsonResponse
from django.http import HttpResponse
from django.shortcuts import render
from .models import ScanResult
from .models import AmassScan
import whois
import sublist3r
import re
import logging






def whois_view(request):
    domain = request.POST.get('domain')
    print("Domain Submitted:", domain)  # Debugging the form data
    if domain:
        # Perform Whois lookup here
        whois_result = f"Sample Whois data for {domain}"
    else:
        whois_result = "No domain entered."

    # Make sure 'exception_notes' is passed if required in the template
    return render(request, 'tools/modal_whois.html', {'whois_result': whois_result})





def index(request):
    return render(request, 'tools/index.html')

def sublist3r_scan(request):
    """
    Handles Sublist3r scanning.
    """
    if request.method == 'POST':
        domain = request.POST.get('domain')
        if domain:
            try:
                subdomains = sublist3r.main(domain, 40, None, ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=None)
                return JsonResponse({'status': 'success', 'subdomains': subdomains})
            except Exception as e:
                return JsonResponse({'status': 'error', 'message': str(e)})
    return render(request, 'tools/modal_sublist3r.html')


# WHOIS Lookup Functionality
def whois_lookup_view(request):
    if request.method == 'POST':
        try:
            domain_name = request.POST.get('domain_name')
            if domain_name:
                whois_data = fetch_whois_data(domain_name)
                if whois_data:
                    processed_data = {k: str(v) for k, v in whois_data.items() if v}
                    return JsonResponse({'status': 'success', 'data': processed_data})
                return JsonResponse({'status': 'error', 'message': 'WHOIS data could not be retrieved.'})
            else:
                return JsonResponse({'status': 'error', 'message': 'No domain provided.'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)})

    return JsonResponse({'status': 'error', 'message': 'Invalid request method.'})


def fetch_whois_data(domain_name):
    try:
        domain_info = whois.whois(domain_name)
        return domain_info
    except Exception as e:
        print(f"Error fetching WHOIS data: {e}")
        return None

logger = logging.getLogger(__name__)

def get_whois_info(domain):
    try:
        # Run the whois command and capture the output
        logger.debug(f"Running Whois for {domain}")
        result = subprocess.run(['whois', domain], capture_output=True, text=True)
        logger.debug(f"Whois result: {result.stdout}")
        return result.stdout  # Return the result if successful
    except Exception as e:
        logger.error(f"Error fetching Whois info for {domain}: {e}")
        return str(e)  # Return the error message if there is an exception
    


    
# Amass Enumeration Functionality
def amass_scan_view(request):
    """
    View to handle Amass scans.
    """
    if request.method == 'POST':
        domain = request.POST.get('domain')  # Get the domain from the user input

        # Validate the domain
        if not domain or not is_valid_domain(domain):
            return JsonResponse({'status': 'error', 'message': 'Invalid domain name provided.'})

        try:
            # Run the Amass tool
            output = run_amass(domain)

            if output:
                # Save the results in the database
                AmassScan.objects.create(domain=domain, results=output)

                # Parse and return the results
                parsed_results = parse_amass_output(output)
                return JsonResponse({'status': 'success', 'data': parsed_results})

            return JsonResponse({'status': 'error', 'message': 'No output received from Amass.'})

        except subprocess.CalledProcessError as e:
            # Handle subprocess errors
            return JsonResponse({'status': 'error', 'message': f"Command failed: {e.stderr.decode('utf-8')}"})
        except Exception as e:
            # Handle other unexpected errors
            return JsonResponse({'status': 'error', 'message': f"An error occurred: {str(e)}"})

    return render(request, 'tools/modal_amass.html')  # Render the Amass modal template




def run_amass(domain):
    """
    Runs Amass for the given domain and captures the output.
    """
    try:
        # Execute the Amass command
        result = subprocess.run(
            ["amass", "enum", "-d", domain],
            capture_output=True,  # Captures both stdout and stderr
            text=True,            # Ensures output is returned as a string
            check=True,           # Raises CalledProcessError if the command fails
            shell=False           # Avoid using shell=True unless necessary
        )
        return result.stdout  # Return the Amass output
    except subprocess.CalledProcessError as e:
        # Log and return the error
        print(f"Amass error: {e.stderr}")
        return f"Error: {e.stderr}"  # Return the error message to display on the frontend
    except Exception as e:
        print(f"Unexpected error: {e}")
        return f"Error: {str(e)}"


def parse_amass_output(output):
    """
    Parses Amass output into a structured format.
    """
    return [line.strip() for line in output.splitlines() if line.strip()]

def nmap_scan(request):
    if request.method == 'POST':
        target = request.POST.get('target')
        # Use subprocess to run the nmap command
        try:
            result = subprocess.getoutput(f'nmap {target}')
            # Save the result in the database
            ScanResult.objects.create(tool_name='Nmap', target=target, result=result)
            return JsonResponse({'result': result})
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    return render(request, 'tools/modal_nmap.html')  # Ensure this template exists

def whois_scan(request):
    if request.method == 'POST':
        domain = request.POST.get('domain')
        # Use subprocess to execute the 'whois' command
        try:
            result = subprocess.getoutput(f'whois {domain}')
            # Save the result in the database
            ScanResult.objects.create(tool_name='Whois', target=domain, result=result)
            return JsonResponse({'result': result})
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    return render(request, 'tools/modal_whois.html')  # Ensure this template exists

def is_valid_domain(domain):
    """
    Validate the domain format using regex.
    """
    domain_regex = re.compile(
        r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.(?!-)[A-Za-z0-9-]{1,63}(?<!-)$"
    )
    return domain_regex.match(domain) is not None


def zap_scan(request):
    # Your function code here
    return HttpResponse("ZAP scan initiated")      

