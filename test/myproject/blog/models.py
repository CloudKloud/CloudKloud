from django.conf import settings
from django.db import models

class Log(models.Model):
    timestamp = models.TextField(blank=True)
    tag = models.TextField(blank=True)
    content = models.TextField(blank=True)
    


class Automated_Query(models.Model):
    timestamp = models.TextField(blank=True)
    content = models.TextField(blank=True)