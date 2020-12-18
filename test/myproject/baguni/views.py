from django.shortcuts import render
from django.http import HttpResponse
from django.http import HttpResponseRedirect
from baguni.models import Log

import json
from django.core import serializers
from django.core.serializers.json import DjangoJSONEncoder
from django.views.decorators.csrf import csrf_exempt

def baguni(request):
    if request.method == 'POST':
        timestamp = request.POST.get('timestamp','')
        content = request.POST.get('content','')
        tag = request.POST.get('tag','')
        
        ob = Log(timestamp=timestamp, tag=tag, content=content)
        ob.delete()
    logs = Log.objects.all().order_by('timestamp')
    
    context = {'logs':logs}
    return render(request, 'baguni/baguni.html', context)

@csrf_exempt
def comment_write_view(request):
    timestamp = request.POST.get('timestamp','')
    content = request.POST.get('content','')
    tag = request.POST.get('tag','')
    
    
    ob = Log(timestamp=timestamp, tag=tag, content=content)
    ob.save()
    
    return HttpResponse("good")


@csrf_exempt
def post_delete(request):
    timestamp = request.POST.get('timestamp','')
    content = request.POST.get('content','')
    tag = request.POST.get('tag','')
    id = request.POST.get('id','')
    
    ob = Log(timestamp=timestamp, tag=tag, content=content, id=id)
    ob.delete()
    logs = Log.objects.all().order_by('timestamp')
    context = {'logs':logs}
    return render(request, 'baguni/baguni.html', context)