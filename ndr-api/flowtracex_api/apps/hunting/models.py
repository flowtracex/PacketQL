from django.db import models
from django.conf import settings

class Hunt(models.Model):
    TYPE_CHOICES = (('visual', 'Visual'), ('sql', 'SQL'))
    STATUS_CHOICES = (
        ('created', 'Created'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    )
    CONFIDENCE_CHOICES = (
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
    )

    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, default='')
    hypothesis = models.TextField(blank=True, default='')
    type = models.CharField(max_length=20, choices=TYPE_CHOICES, default='visual')
    log_source = models.CharField(max_length=50, default='conn')
    query = models.TextField(blank=True, default='')        # Legacy field
    sql_query = models.TextField(blank=True, default='')    # For SQL hunts
    conditions = models.JSONField(default=list, blank=True)  # For visual hunts
    time_range = models.CharField(max_length=50, default='Last 24h')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='created')
    matches_found = models.IntegerField(default=0)
    data_processed = models.FloatField(default=0)
    confidence = models.CharField(max_length=10, choices=CONFIDENCE_CHOICES, default='LOW')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_run_at = models.DateTimeField(null=True, blank=True)
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return self.name

class HuntResult(models.Model):
    hunt = models.ForeignKey(Hunt, on_delete=models.CASCADE, related_name='results')
    created_at = models.DateTimeField(auto_now_add=True)
    duration = models.FloatField(default=0.0)
    matches_found = models.IntegerField(default=0)
    status = models.CharField(max_length=20, default='completed')
    result_data = models.JSONField(default=dict)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.hunt.name} - {self.created_at}"
