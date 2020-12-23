from django.shortcuts import render
from django.http import HttpResponse

from .models import accessKeyIDPW
from django.views.decorators.csrf import csrf_exempt
from .auth import *
from baguni.models import Log
from regist.models import accessKeyIDPW
# Create your views here.

# Authentication

def auth_check():
    db = accessKeyIDPW.objects.all()
    if not db:
        return "incomplete"
    else:
        return "complete"

def regist(request):

    return render(request, 'regist/regist.html')

def login(request):
    test = Log.objects.all()
   
    db = accessKeyIDPW.objects.all()
    db.delete()
    if request.method == 'POST':
        
        username = request.POST['username']
        password = request.POST['password']
        region = request.POST['region']
        role = request.POST['rolename']
        result = auth(username, password)
        
        if result == True:
            ob = accessKeyIDPW(accesskeyid=username, secretaccesskey=password, awsconfigregion=region, awsrolename=role)
            ob.save()
            return render(request, 'map/MainPage2.html',{'regionname' : region, 'roleid': role, 'auth':auth_check()})
        else:
            return render(request, 'regist/regist.html', {'error' : 'Invalid Access Key or Secret Key', 'auth':auth_check()})
    else:
        return render(request, 'regist/regist.html', { 'auth':auth_check()})