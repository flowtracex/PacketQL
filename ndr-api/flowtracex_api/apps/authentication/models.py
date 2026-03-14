from django.contrib.auth.models import AbstractUser
from django.db import models

class User(AbstractUser):
    ROLE_CHOICES = (
        ('admin', 'Admin'),
        ('analyst', 'Analyst'),
        ('viewer', 'Viewer'),
    )
    
    full_name = models.CharField(max_length=255, blank=True)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='analyst')
    avatar = models.URLField(max_length=500, blank=True, null=True)
    
    def __str__(self):
        return self.username
