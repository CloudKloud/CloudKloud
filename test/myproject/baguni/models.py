from django.db import models
from django.conf import settings

class Log(models.Model):
    
    timestamp = models.TextField(blank=True)
    tag = models.TextField(blank=True)
    content = models.TextField(blank=True)