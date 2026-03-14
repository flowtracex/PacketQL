from django.db import models
from django.conf import settings

class Rule(models.Model):
    SEVERITY_CHOICES = (('critical', 'Critical'), ('high', 'High'), ('medium', 'Medium'), ('low', 'Low'))
    TYPE_CHOICES = (('threshold', 'Threshold'), ('query', 'Query'))

    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    type = models.CharField(max_length=20, choices=TYPE_CHOICES)
    query = models.TextField() # SQL or condition JSON
    threshold = models.IntegerField(default=1)
    time_window = models.CharField(max_length=20, default='5m')
    enabled = models.BooleanField(default=True)
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    mitre_tactic = models.CharField(max_length=100, blank=True)

    def __str__(self):
        return self.name

class RuleStats(models.Model):
    rule = models.OneToOneField(Rule, on_delete=models.CASCADE, related_name='stats')
    detections_24h = models.IntegerField(default=0)
    detections_7d = models.IntegerField(default=0)
    false_positive_rate = models.FloatField(default=0.0)
    last_triggered = models.DateTimeField(null=True, blank=True)
    avg_execution_time_ms = models.IntegerField(default=0)
