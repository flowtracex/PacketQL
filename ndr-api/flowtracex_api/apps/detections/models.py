from django.db import models
from django.utils import timezone

from django.utils.translation import gettext_lazy as _

class Alert(models.Model):
    class Severity(models.TextChoices):
        CRITICAL = 'critical', _('Critical')
        HIGH = 'high', _('High')
        MEDIUM = 'medium', _('Medium')
        LOW = 'low', _('Low')
        INFO = 'info', _('Info')

    class Status(models.TextChoices):
        OPEN = 'open', _('Open')
        INVESTIGATING = 'investigating', _('Investigating')
        RESOLVED = 'resolved', _('Resolved')

    class Verdict(models.TextChoices):
        TRUE_POSITIVE = 'true_positive', _('True Positive')
        FALSE_POSITIVE = 'false_positive', _('False Positive')
        BENIGN = 'benign', _('Benign')
        UNKNOWN = 'unknown', _('Unknown')

    name = models.CharField(max_length=255)
    description = models.TextField()
    severity = models.CharField(max_length=20, choices=Severity.choices, default=Severity.MEDIUM)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.OPEN)
    verdict = models.CharField(max_length=20, choices=Verdict.choices, default=Verdict.UNKNOWN)
    confidence = models.IntegerField(default=0)
    mitre_id = models.CharField(max_length=50, blank=True, null=True)
    mitre_tactic = models.CharField(max_length=100, blank=True, null=True)
    source_ip = models.GenericIPAddressField(blank=True, null=True)
    destination_ip = models.GenericIPAddressField(blank=True, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    # Store complex nested data as JSON for flexibility in Demo mode
    blast_radius = models.JSONField(default=dict)
    asset_context = models.JSONField(default=dict)
    risk_context = models.JSONField(default=dict)

    def __str__(self):
        return self.name

class AlertSignal(models.Model):
    alert = models.ForeignKey(Alert, related_name='signals', on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    explanation = models.TextField()
    detection_logic = models.JSONField(default=dict)
    evidence = models.JSONField(default=list)

    def __str__(self):
        return self.name
