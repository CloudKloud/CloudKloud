from django.http import HttpResponse
from django.shortcuts import render

from baguni.models import Log
from blog.models import Automated_Query

# Custom export funcs
from django.http import HttpResponse
from .s3filter import *
from .iamfilter import *
from .rdsfilter import *
from .ec2filter import *
from .ir import *
import json
from django.core import serializers
from django.core.serializers.json import DjangoJSONEncoder
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse


##########


def default(request):
    return render(request, 'Default.html')


def maps(request):
    return render(request, 'map/readCSV.html')



def index(request):
    
    return render(request, 'blog/MainPage.html')

# Link
def link(request):
    return render(request, 'blog/link.html')


# LOG EXPLORER 

def logExplorer(request):
    
    return render(request, 'blog/logExplorer.html')

def Viewer(request):
    
    return render(request, 'blog/viewer.html')

@csrf_exempt
def comment_write_view(request):
    #post = get_object_or_404(blog, id=pk)
    timestamp = request.POST.get('timestamp','')
    content = request.POST.get('content','')
    tag = request.POST.get('tag','')
    
    ob = Log(timestamp=timestamp, tag=tag, content=content)
    ob.save()
    
    return JsonResponse({'message':'success'})




# Automated Query

def QueryMain(request):

    
    return render(request, 'blog/queryMain.html')


def Query(request, id):
    context = {
        'id' : id,
    }
    return render(request, 'blog/query.html', context)

def ip_query(request, id):
    context = {
        'id' : id,
    }
    return render(request, 'blog/ipquery.html', context)

def iamkey_query(request, id):
    context = {
        'id' : id,
    }
    return render(request, 'blog/iamkeyquery.html', context)

# IR
def IR(request):
    return render(request, 'blog/incidentResponse.html')

def mitigation(request):
    response = mitigate_automate()
    return JsonResponse(response)

def ec2_list(request):
    response = instance_list()
    return JsonResponse(response)


# DB

list = [List_Objects, S3_Create_Data, S3_Delete_Data, Call_API_Abnormal_Object, Access_Logging_Disabled, Modify_Policy_BucketObject,Modify_Bucket_Policy,Access_System, 
        PentestSystems, NetworkPermissions, LoggingConfigurationModified, UserPermissions, ResourcePermissions, RootCredentialUsage, ComputingResource,
        DescribeDBInstances, DeleteDBData, AddUser, GrantAuth, RDSAPICall, ModifyDBParameterGroup, DeleteDBParameterGroup, StopDBInstance, DeleteDBInstance, SusOSAPI, StopWatchLogs, RDSAccessDenied,
        ShellCMDyum, ShellCMDsudo, ShellCMDservice, ShellCMDcron, VPCFLOWreject, CreateInstances, DeleteInstances, ModifySecurityGroupRule, PentestSystems]

def background(request, id):
    list[int(id)]()
    return HttpResponse(id)
