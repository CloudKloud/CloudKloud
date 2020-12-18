from django.db import models

# Create your models here.
class accessKeyIDPW(models.Model):
    accesskeyid = models.TextField(blank=False, unique=True)
    secretaccesskey = models.TextField(blank=False, unique=True)