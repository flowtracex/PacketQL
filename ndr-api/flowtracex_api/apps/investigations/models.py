from django.db import models
from django.conf import settings
from django.utils import timezone

class Investigation(models.Model):
    SEVERITY_CHOICES = (('critical', 'Critical'), ('high', 'High'), ('medium', 'Medium'), ('low', 'Low'))
    STATUS_CHOICES = (('active', 'Active'), ('closed', 'Closed'))

    name = models.CharField(max_length=255)
    description = models.TextField()
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    assigned_to = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='assigned_investigations')
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='owned_investigations')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    segment = models.CharField(max_length=100, blank=True)
    mitre_tactic = models.CharField(max_length=100, blank=True)
    
    # Verdict
    verdict = models.CharField(max_length=50, blank=True)
    justification = models.TextField(blank=True)

    def __str__(self):
        return self.name

class InvestigationAlert(models.Model):
    investigation = models.ForeignKey(Investigation, on_delete=models.CASCADE, related_name='alerts')
    alert_id = models.CharField(max_length=100) # ID from DuckDB/Parquet (might be UUID or Int, storing as String for flexibility)
    added_at = models.DateTimeField(auto_now_add=True)

class InvestigationTimeline(models.Model):
    investigation = models.ForeignKey(Investigation, on_delete=models.CASCADE, related_name='timeline')
    timestamp = models.DateTimeField(default=timezone.now)
    type = models.CharField(max_length=50) # status_change, note, alert_added, etc.
    description = models.CharField(max_length=255)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)

class Note(models.Model):
    investigation = models.ForeignKey(Investigation, on_delete=models.CASCADE, related_name='notes')
    text = models.TextField()
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

class EvidenceMeta(models.Model):
    investigation = models.ForeignKey(Investigation, on_delete=models.CASCADE, related_name='evidence')
    filename = models.CharField(max_length=255)
    size = models.BigIntegerField()
    type = models.CharField(max_length=100)
    uploaded_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    description = models.TextField(blank=True)
    file_path = models.CharField(max_length=500) # Path on filesystem

