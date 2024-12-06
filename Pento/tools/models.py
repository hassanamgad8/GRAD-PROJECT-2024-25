from django.db import models

class ScanResult(models.Model):
    tool_name = models.CharField(max_length=50)
    target = models.CharField(max_length=100)
    result = models.TextField()
    scanned_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'{self.tool_name} - {self.target}'
