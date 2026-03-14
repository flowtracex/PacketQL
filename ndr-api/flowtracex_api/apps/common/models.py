from django.db import models
from django.conf import settings

class Notification(models.Model):
    TYPE_CHOICES = (
        ('alert', 'Alert'),
        ('system', 'System'),
        ('mention', 'Mention'),
    )
    
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='notifications')
    type = models.CharField(max_length=20, choices=TYPE_CHOICES)
    title = models.CharField(max_length=255)
    message = models.TextField()
    read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    link_to = models.CharField(max_length=500, blank=True, null=True)

    def __str__(self):
        return f"{self.title} - {self.user.username}"

class MitreTactic(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    external_id = models.CharField(max_length=50, unique=True, null=True) # e.g. TA0001
    
    def __str__(self):
        return self.name

class MitreTechnique(models.Model):
    tactic = models.ForeignKey(MitreTactic, on_delete=models.CASCADE, related_name='techniques')
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    external_id = models.CharField(max_length=50, unique=True, null=True) # e.g. T1001
    
    def __str__(self):
        return self.name
