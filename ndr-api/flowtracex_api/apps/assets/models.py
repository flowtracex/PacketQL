from django.db import models

class Asset(models.Model):
    ip = models.GenericIPAddressField(unique=True)
    hostname = models.CharField(max_length=255, blank=True)
    type = models.CharField(max_length=50, default='unknown') # server, workstation, iot
    os = models.CharField(max_length=100, blank=True)
    mac_address = models.CharField(max_length=17, blank=True)
    vuln_count = models.IntegerField(default=0)
    risk_score = models.IntegerField(default=0)
    segment = models.CharField(max_length=100, blank=True)
    last_seen = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    
    # For threat linked tab
    is_threat = models.BooleanField(default=False)
    threat_confidence = models.IntegerField(default=0)

    def __str__(self):
        return f"{self.ip} ({self.hostname})"
