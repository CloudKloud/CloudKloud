import boto3
import time
import json
import datetime
from regist.models import accessKeyIDPW

AWS_DEFAULT_REGION = "ap-northeast-2"

def cloudtrail_trailcheck():
    db = accessKeyIDPW.objects.all()

    AWS_ACCESS_KEY_ID = db[0].accesskeyid
    AWS_SECRET_ACCESS_KEY = db[0].secretaccesskey
    client = boto3.client('cloudtrail', aws_access_key_id=AWS_ACCESS_KEY_ID,
                    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                    region_name=AWS_DEFAULT_REGION)
    result = client.describe_trails()
    if result['trailList'] != []:
        return '설정 완료'
    return '미설정'

def cloudtrail_MRcheck(): #multi region check
    db = accessKeyIDPW.objects.all()

    AWS_ACCESS_KEY_ID = db[0].accesskeyid
    AWS_SECRET_ACCESS_KEY = db[0].secretaccesskey
    client = boto3.client('cloudtrail', aws_access_key_id=AWS_ACCESS_KEY_ID,
                    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                    region_name=AWS_DEFAULT_REGION)
    result = client.describe_trails()
    check = False
    try:
        if result['trailList'] == []:
            pass
        else:
            for i in result['trailList']:
                if (i['IsMultiRegionTrail'] == True):
                        return '설정 완료'
    except:
        pass
    return '미설정'
    

def cloudtrail_watchcheck(): #multi region check
    db = accessKeyIDPW.objects.all()

    AWS_ACCESS_KEY_ID = db[0].accesskeyid
    AWS_SECRET_ACCESS_KEY = db[0].secretaccesskey
    client = boto3.client('cloudtrail', aws_access_key_id=AWS_ACCESS_KEY_ID,
                    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                    region_name=AWS_DEFAULT_REGION)
    result = client.describe_trails()
    check = False
    try:
        if result['trailList'] == []:
            pass
        else:
            for i in result['trailList']:
                if (i['IsMultiRegionTrail'] == True):
                        check = True
                try:
                    i['CloudWatchLogsRoleArn']
                except:
                    check = False
                    pass
                if check == True:
                    return '설정 완료'
    except:
        pass

    return '미설정'

def s3_check():
    db = accessKeyIDPW.objects.all()

    AWS_ACCESS_KEY_ID = db[0].accesskeyid
    AWS_SECRET_ACCESS_KEY = db[0].secretaccesskey
    client = boto3.client('cloudtrail', aws_access_key_id=AWS_ACCESS_KEY_ID,
                    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                    region_name=AWS_DEFAULT_REGION)
    try:
        result = client.get_event_selectors(TrailName='ck-trail')
        temp = result['EventSelectors'][0]['DataResources']
        if temp[0]['Type'] == 'AWS::S3::Object' and temp[0]['Values'][0] == 'arn:aws:s3':
            return '설정 완료'
    except:
        pass
    return '미설정'

def rds_securitygroup_check():
    db = accessKeyIDPW.objects.all()

    AWS_ACCESS_KEY_ID = db[0].accesskeyid
    AWS_SECRET_ACCESS_KEY = db[0].secretaccesskey
    ec2 = boto3.client('ec2', aws_access_key_id=AWS_ACCESS_KEY_ID,
                    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                    region_name=AWS_DEFAULT_REGION)
    try:
        result = ec2.describe_security_groups(
            GroupNames=[
            'ck-SecurityGroup',
            ]
        )
        temp = result['SecurityGroups'][0]['IpPermissions'][0]
        if temp['FromPort'] == 3306 and temp['IpProtocol'] == 'tcp':
            return '설정 완료'
    except:
        return '미설정'
    return '미설정'

def rds_exportlog_check():
    db = accessKeyIDPW.objects.all()

    AWS_ACCESS_KEY_ID = db[0].accesskeyid
    AWS_SECRET_ACCESS_KEY = db[0].secretaccesskey
    rds = boto3.client('rds', aws_access_key_id=AWS_ACCESS_KEY_ID,
                    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                    region_name=AWS_DEFAULT_REGION)
    result = rds.describe_db_instances()
    if result['DBInstances'] == []:
        return '미설정'
    for i in result['DBInstances']:
        try:
            if i['EnabledCloudwatchLogsExports'] != ['error', 'general', 'slowquery']:
                return '미설정 db 존재'
        except:
            return '미설정 db 존재'
    return '설정 완료'

def rds_paragrp_check():
    db = accessKeyIDPW.objects.all()

    AWS_ACCESS_KEY_ID = db[0].accesskeyid
    AWS_SECRET_ACCESS_KEY = db[0].secretaccesskey
    rds = boto3.client('rds', aws_access_key_id=AWS_ACCESS_KEY_ID,
                    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                    region_name=AWS_DEFAULT_REGION)
    try:
        result = rds.describe_db_parameters(DBParameterGroupName='ck-parametergroup')
        for i in result['Parameters']:
            if i['ParameterName'] == 'general_log' and i['ParameterValue'] != '1':
                return '미설정'
            if i['ParameterName'] == 'slow_query_log' and i['ParameterValue'] != '1':
                return '미설정'
            if i['ParameterName'] == 'log_output' and i['ParameterValue'] != 'FILE':
                return '미설정'
        result = rds.describe_db_instances()
        print(result)
        for i in result['DBInstances']:
            if i['DBParameterGroups'][0]['DBParameterGroupName'] != 'ck-parametergroup':
                return '미설정'
    except:
        return '미설정'
    return '설정 완료'

def ec2_iam_check():
    db = accessKeyIDPW.objects.all()

    AWS_ACCESS_KEY_ID = db[0].accesskeyid
    AWS_SECRET_ACCESS_KEY = db[0].secretaccesskey
    ec2 = boto3.client('ec2', aws_access_key_id=AWS_ACCESS_KEY_ID,
                    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                    region_name=AWS_DEFAULT_REGION)
    result = ec2.describe_instances()
    for i in result['Reservations']:
        try:
            if i['Instances'][0]['IamInstanceProfile']['Arn'].split('/')[1] == 'CloudWatchAgent':
                return '설정 완료'
        except:
            pass
    return '미설정'

def ec2_watchagent_check():
    db = accessKeyIDPW.objects.all()

    AWS_ACCESS_KEY_ID = db[0].accesskeyid
    AWS_SECRET_ACCESS_KEY = db[0].secretaccesskey
    logs = boto3.client('logs', aws_access_key_id=AWS_ACCESS_KEY_ID,
                    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                    region_name=AWS_DEFAULT_REGION)
    result = logs.describe_log_groups()
    tmp = 0
    for i in result['logGroups']:
        if i['logGroupName'] == 'messages' or i['logGroupName'] == 'secure' or i['logGroupName'] == 'lastlog' or i['logGroupName'] == 'yum.log':
            tmp+=1
    if tmp == 4:
        return '설정 완료'
    
    return '미설정'

def ec2_logconf_check():
    db = accessKeyIDPW.objects.all()

    AWS_ACCESS_KEY_ID = db[0].accesskeyid
    AWS_SECRET_ACCESS_KEY = db[0].secretaccesskey
    logs = boto3.client('logs', aws_access_key_id=AWS_ACCESS_KEY_ID,
                    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                    region_name=AWS_DEFAULT_REGION)
    result = logs.describe_log_groups()
    for i in result['logGroups']:
        if i['logGroupName'] == 'ck-ShellCMDlog':
            return '설정 완료'
    return '미설정'

