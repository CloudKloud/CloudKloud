from django.contrib import admin
from blog.models import *  # models.py로부터 Post 모델을 가져온다.

admin.site.register(Log)  # Post를 관리자 페이지에 등록한다.
admin.site.register(Automated_Query)