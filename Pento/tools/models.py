from django.db import models

class ScanResult(models.Model):
    tool_name = models.CharField(max_length=50)
    target = models.CharField(max_length=100)
    result = models.TextField()
    scanned_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'{self.tool_name} - {self.target}'

class WhoisLookup(models.Model):
    domain = models.CharField(max_length=100)
    data = models.TextField()  # Store WHOIS data as JSON or plain text
    scanned_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"WHOIS for {self.domain} on {self.scanned_at}"


class AmassScan(models.Model):
    domain = models.CharField(max_length=100)
    results = models.TextField()  # Store Amass results as plain text
    scanned_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Amass Scan for {self.domain} on {self.scanned_at}"
    


class ToolLog(models.Model):
    tool_name = models.CharField(max_length=100)
    scan_date = models.DateTimeField(auto_now_add=True)
    result = models.TextField()

    def __str__(self):
        return f"{self.tool_name} - {self.scan_date}"