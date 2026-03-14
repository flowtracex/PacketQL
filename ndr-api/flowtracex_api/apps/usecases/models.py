from django.db import models

class UseCase(models.Model):
    CATEGORY_CHOICES = (
        ('malware', 'Malware'),
        ('exfiltration', 'Exfiltration'), 
        ('lateral', 'Lateral Movement'),
        ('recon', 'Reconnaissance')
    )

    name = models.CharField(max_length=255)
    description = models.TextField()
    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES)
    signals = models.JSONField(default=list) 

    def __str__(self):
        return self.name

class UseCaseStage(models.Model):
    use_case = models.ForeignKey(UseCase, on_delete=models.CASCADE, related_name='stages')
    label = models.CharField(max_length=100)
    name = models.CharField(max_length=255)
    detection_logic = models.TextField() # SQL
    thresholds = models.JSONField(default=dict)
    required_fields = models.JSONField(default=list)
    grouping_entity = models.CharField(max_length=50)

    def __str__(self):
        return f"{self.use_case.name} - {self.label}"
