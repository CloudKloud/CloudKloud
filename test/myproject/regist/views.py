from django.shortcuts import render
from django.http import HttpResponse

from .models import accessKeyIDPW
from django.views.decorators.csrf import csrf_exempt
from .auth import *
from baguni.models import Log
# Create your views here.

def regist(request):

    return render(request, 'regist/regist.html')

def login(request):
    test = Log.objects.all()
   
    db = accessKeyIDPW.objects.all()
    db.delete()
    if request.method == 'POST':
        
        username = request.POST['username']
        password = request.POST['password']
        result = auth(username, password)
        
        if result == True:
            ob = accessKeyIDPW(accesskeyid=username, secretaccesskey=password)
            ob.save()
            return render(request, 'map/MainPage2.html')
        else:
            return render(request, 'regist/regist.html', {'error' : 'Invalid Access Key or Secret Key'})
    else:
        return render(request, 'regist/regist.html')