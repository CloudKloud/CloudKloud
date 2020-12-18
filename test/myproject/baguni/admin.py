from django.contrib import admin
from .models import Log  # models.py로부터 Post 모델을 가져온다.

admin.site.register(Log)