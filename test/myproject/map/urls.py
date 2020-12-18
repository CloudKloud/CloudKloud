from django.urls import path

from . import views

urlpatterns = [
    path('', views.regionjson, name='maps'),
]