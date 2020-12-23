from django.shortcuts import render
from django.http import HttpResponse
# Create your views here.
from .check import *
from regist.models import accessKeyIDPW

def auth_check():
    db = accessKeyIDPW.objects.all()
    if not db:
        return "incomplete"
    else:
        return "complete"

def check(request):

    
        try:
                context = {
                'trailcheck': cloudtrail_trailcheck(),
                'MRcheck' : cloudtrail_MRcheck(),
                'trailwatchcheck' : cloudtrail_watchcheck(),
                's3check' : s3_check(),
                'rdssecugrpcheck' : rds_securitygroup_check(),
                'rdsexportlogcheck' : rds_exportlog_check(),
                'rdsparagrpcheck' : rds_paragrp_check(),
                'ec2iamcheck' : ec2_iam_check(),
                'ec2watchagentcheck' : ec2_watchagent_check(),
                'ec2logconfcheck' : ec2_logconf_check(),
                'auth' : auth_check()
                }
        except Exception as ex:
                print(ex)
                return render(request, 'regist/regist.html', {'auth':auth_check()})
        return render(request, 'check/check.html', context)


