from django.db import models

class LogEntry(models.Model):
    timestamp = models.DateTimeField()
    type = models.CharField(max_length=50) # dns, http, flow, etc
    severity = models.CharField(max_length=20, default='info')
    content = models.TextField() # JSON or raw string
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    dest_ip = models.GenericIPAddressField(null=True, blank=True)
    protocol = models.CharField(max_length=20, blank=True)

    def __str__(self):
        return f"{self.timestamp} - {self.type}"
