from django.db import models
from django.conf import settings

class SystemIdentity(models.Model):
    hostname = models.CharField(max_length=255)
    version = models.CharField(max_length=50)
    deployed_at = models.DateTimeField(auto_now_add=True)
    license_key = models.CharField(max_length=255)
    region = models.CharField(max_length=50)

class Preferences(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    theme = models.CharField(max_length=20, default='dark')
    timezone = models.CharField(max_length=50, default='UTC')
    alerts_per_page = models.IntegerField(default=10)
    notifications_enabled = models.BooleanField(default=True)

class APIKey(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    key_prefix = models.CharField(max_length=10)
    key_hash = models.CharField(max_length=255) # Store hash, not full key
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)

class AuditLog(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    action = models.CharField(max_length=100)
    target = models.CharField(max_length=255)
    ip = models.GenericIPAddressField(null=True, blank=True)
    details = models.TextField(blank=True)
