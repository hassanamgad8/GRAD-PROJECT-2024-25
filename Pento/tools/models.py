from django.db import models
from django.utils.timezone import now

class ScanConfig(models.Model):
    user = models.ForeignKey('auth.User', on_delete=models.CASCADE, help_text="User who created the scan configuration.")
    profile = models.CharField(
        max_length=50,
        choices=[
            ("quick", "Quick Scan"),
            ("advanced", "Advanced Scan"),
            ("custom", "Custom Scan")
        ],
        default="quick",
        help_text="The scan profile used."
    )
    target = models.URLField(help_text="Target URL for the scan.")
    options = models.JSONField(help_text="JSON storing all scan options, e.g., XSS, SQLMap, custom rules.")
    hidden_params = models.BooleanField(default=False, help_text="Enable brute-forcing hidden parameters.")
    tamper_scripts = models.JSONField(
        null=True, blank=True, help_text="List of tamper scripts for WAF bypass (e.g., space2comment)."
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.username}'s {self.profile} config for {self.target}"


class Report(models.Model):
    # Added 'scan_type' field
    scan_type = models.CharField(
        max_length=100,
        choices=[
            ('port_scanner', 'Port Scanner'),
            ('domain_finder', 'Domain Finder'),
            ('subdomain_finder', 'Subdomain Finder'),
            ('website_scanner', 'Website Scanner'),
            ('whois_lookup', 'Whois Lookup'),
            ('dns_lookup', 'DNS Lookup'),
            # Add other scan types as needed
        ],
        help_text="Type of scan performed."
    )
    
    target = models.CharField(max_length=255, help_text="The target domain, IP, or URL of the scan.")
    result = models.TextField(help_text="The raw result of the scan.")
    
    # Removed duplicate 'status' field and kept one definition
    status = models.CharField(
        max_length=50,
        choices=[
            ('queued', 'Queued'),
            ('running', 'Running'),
            ('completed', 'Completed'),
            ('failed', 'Failed')
        ],
        default='queued',
        help_text="The current status of the scan."
    )
    
    # Removed duplicate 'progress' field and kept one definition
    progress = models.IntegerField(default=0, help_text="Progress percentage of the scan.")
    
    timestamp = models.DateTimeField(auto_now_add=True, help_text="The time when the scan was initiated.")
    updated_at = models.DateTimeField(auto_now=True, help_text="The time when the scan was last updated.")
    created_by = models.CharField(max_length=100, null=True, blank=True, help_text="The user who initiated the scan.")
    
    scan_config = models.ForeignKey(
        ScanConfig, null=True, blank=True, on_delete=models.SET_NULL, help_text="Configuration used for the scan."
    )
    
    severity_summary = models.JSONField(
        null=True, blank=True, help_text="Summary of vulnerabilities grouped by severity levels (Critical, High, etc.)."
    )
    export_path = models.CharField(max_length=255, null=True, blank=True, help_text="Path to the exported report file.")

    class Meta:
        ordering = ['-timestamp']
        verbose_name = "Scan Report"
        verbose_name_plural = "Scan Reports"

    def __str__(self):
        return f"{self.scan_type} - {self.target} ({self.timestamp.strftime('%Y-%m-%d %H:%M:%S')})"


class Host(models.Model):
    hostname = models.CharField(max_length=255, unique=True)
    ip_address = models.GenericIPAddressField(unique=True)

    def __str__(self):
        return self.hostname


class Port(models.Model):
    port_number = models.IntegerField()
    protocol = models.CharField(max_length=50)
    service = models.CharField(max_length=100, null=True, blank=True)
    host = models.ForeignKey(Host, on_delete=models.CASCADE, related_name="ports")

    def __str__(self):
        return f"{self.port_number}/{self.protocol}"


class Technology(models.Model):
    name = models.CharField(max_length=255)
    version = models.CharField(max_length=100, null=True, blank=True)
    host = models.ForeignKey(Host, on_delete=models.CASCADE, related_name="technologies")

    def __str__(self):
        return f"{self.name} {self.version or ''}"


class Finding(models.Model):
    description = models.TextField()
    target = models.ForeignKey(Host, on_delete=models.CASCADE, related_name="findings")
    risk_level = models.CharField(
        max_length=50,
        choices=[
            ("info", "Info"),
            ("low", "Low"),
            ("medium", "Medium"),
            ("high", "High"),
        ],
    )
    source = models.CharField(max_length=255)
    scan_date = models.DateTimeField(auto_now_add=True)
    vulnerability_type = models.CharField(
        max_length=50,
        choices=[
            ("csrf", "Cross-Site Request Forgery (CSRF)"),
            ("xss", "Cross-Site Scripting (XSS)"),
            ("sqli", "SQL Injection (SQLi)"),
            ("lfi", "Local File Inclusion (LFI)"),
            ("rfi", "Remote File Inclusion (RFI)"),
            ("open_redirect", "Open Redirect"),
            ("sensitive_data", "Sensitive Data Exposure"),
        ],
        help_text="The type of vulnerability identified."
    )
    proof_of_concept = models.TextField(null=True, blank=True, help_text="Details or payload used for exploitation.")

    def __str__(self):
        return f"{self.description} - {self.risk_level}"
