from django.shortcuts import render
from django.http import JsonResponse
from .METAlogic.exploits import identify_ip_and_os  # Import the exploit logic

def ip_os_identification_view(request):
    if request.method == "POST":
        target_ip = request.POST.get("ip")
        print(f"Received IP: {target_ip}")  # Debugging line
        if not target_ip:
            return JsonResponse({"status": "error", "message": "Target IP is required."}, status=400)

        result = identify_ip_and_os(target_ip)
        print(f"Result: {result}")  # Debugging line
        return JsonResponse(result)
