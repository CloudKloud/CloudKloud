import boto3
import time
import json
import datetime
from regist.models import accessKeyIDPW

db = accessKeyIDPW.objects.all()
if db:
    AWS_ACCESS_KEY_ID = db[0].accesskeyid
    AWS_SECRET_ACCESS_KEY = db[0].secretaccesskey
    AWS_DEFAULT_REGION = db[0].awsconfigregion


    logs = boto3.client('logs',
                        aws_access_key_id=AWS_ACCESS_KEY_ID,
                          aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                          region_name=AWS_DEFAULT_REGION)

    s3 = boto3.client('s3',aws_access_key_id=AWS_ACCESS_KEY_ID,
                          aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                          region_name=AWS_DEFAULT_REGION)

# IAM : 총 7개 함수 (목요일에 다시 업데이트할 예정. 그전까지는 여기!)
# s3에도 filterPattern에 eventSource = "s3.amazonaws.com" 추가해야함 <- 나중에 다시 한번에 추가하자 

# 1. 침투 테스트 시스템에서 API 호출
def PentestSystems():
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern= '{ $.eventSource = "iam.amazonaws.com" && ($.userAgent="*kali*" || $.userAgent="*parrot*" || $.userAgent="*pentoo*")}', 
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern= '{ $.eventSource = "iam.amazonaws.com" && ($.userAgent="*kali*" || $.userAgent="*parrot*" || $.userAgent="*pentoo*")}'  
            )
        for i in log['events']:
            result = {"id" : cnt, "timestamp": datetime.datetime.fromtimestamp(i['timestamp']/1000).strftime('%Y-%m-%d %H:%M:%S'), "message": i['message']}
            cnt += 1
            output.append(result)

        if log.get("nextToken"):
            next_token = log["nextToken"]
        else:
            
            break
    
    ret = json.dumps({"total" : cnt, "totalNotFiltered" : cnt, "rows" : output})
    response = s3.put_object(Body=ret,
                            Bucket='threatitem',
                            Key='IAM/8' )
    return response


# 2. 네트워크 액세스 권한 변경(보안 그룹, 라우트, ACL)
def NetworkPermissions():
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='{$.eventSource = "iam.amazonaws.com" && ($.eventName="CreateSecurityGroup" || $.eventName="DescribeInstances")}',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='{$.eventSource = "iam.amazonaws.com" && ($.eventName="CreateSecurityGroup" || $.eventName="DescribeInstances")}'
            )
        for i in log['events']:
            result = {"id" : cnt, "timestamp": datetime.datetime.fromtimestamp(i['timestamp']/1000).strftime('%Y-%m-%d %H:%M:%S'), "message": i['message']}
            cnt += 1
            output.append(result)

        if log.get("nextToken"):
            next_token = log["nextToken"]
        else:
            print(cnt) #총 개수 출력
            break
    
    ret = json.dumps({"total" : cnt, "totalNotFiltered" : cnt, "rows" : output})
    response = s3.put_object(Body=ret,
                            Bucket='threatitem',
                            Key='IAM/9' )
    return response


# 3. CloudTrail로깅 중단, 기존 로그 삭제
def LoggingConfigurationModified():
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='{$.eventSource = "iam.amazonaws.com" && $.eventName="StopLogging"}',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='{$.eventSource = "iam.amazonaws.com" && $.eventName="StopLogging"}'
            )
        for i in log['events']:
            result = {"id" : cnt, "timestamp": datetime.datetime.fromtimestamp(i['timestamp']/1000).strftime('%Y-%m-%d %H:%M:%S'), "message": i['message']}
            cnt += 1
            output.append(result)

        if log.get("nextToken"):
            next_token = log["nextToken"]
        else:
            print(cnt) #총 개수 출력
            break
    
    ret = json.dumps({"total" : cnt, "totalNotFiltered" : cnt, "rows" : output})
    response = s3.put_object(Body=ret,
                            Bucket='threatitem',
                            Key='IAM/10' )
    return response
    

# 4. IAM 사용자, 그룹 또는 정책을 추가/변경/삭제
def UserPermissions():
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='{$.eventSource = "iam.amazonaws.com" && ($.eventName="AttachUserPolicy" || $.eventName="ListInstanceProfilesForRole")}',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='{$.eventSource = "iam.amazonaws.com" && ($.eventName="AttachUserPolicy" || $.eventName="ListInstanceProfilesForRole")}' 
            )
        for i in log['events']:
            result = {"id" : cnt, "timestamp": datetime.datetime.fromtimestamp(i['timestamp']/1000).strftime('%Y-%m-%d %H:%M:%S'), "message": i['message']}
            cnt += 1
            output.append(result)

        if log.get("nextToken"):
            next_token = log["nextToken"]
        else:
            print(cnt) #총 개수 출력
            break
    
    ret = json.dumps({"total" : cnt, "totalNotFiltered" : cnt, "rows" : output})
    response = s3.put_object(Body=ret,
                            Bucket='threatitem',
                            Key='IAM/11' )
    return response


# 5. 리소스 보안 액세스 정책 변경
def ResourcePermissions():
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='{$.eventSource = "iam.amazonaws.com" && $.eventName="PutBucketPolicy"}',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='{$.eventSource = "iam.amazonaws.com" && $.eventName="PutBucketPolicy"}' 
            )
        for i in log['events']:
            result = {"id" : cnt, "timestamp": datetime.datetime.fromtimestamp(i['timestamp']/1000).strftime('%Y-%m-%d %H:%M:%S'), "message": i['message']}
            cnt += 1
            output.append(result)

        if log.get("nextToken"):
            next_token = log["nextToken"]
        else:
            print(cnt) #총 개수 출력
            break
    
    ret = json.dumps({"total" : cnt, "totalNotFiltered" : cnt, "rows" : output})
    response = s3.put_object(Body=ret,
                            Bucket='threatitem',
                            Key='IAM/12' )
    return response


# 6. 루트 계정 사용
def RootCredentialUsage():
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='{$.eventSource = "iam.amazonaws.com" && $.userIdentity.type="Root"}',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='{$.eventSource = "iam.amazonaws.com" && $.userIdentity.type="Root"}'
            )
        for i in log['events']:
            result = {"id" : cnt, "timestamp": datetime.datetime.fromtimestamp(i['timestamp']/1000).strftime('%Y-%m-%d %H:%M:%S'), "message": i['message']}
            cnt += 1
            output.append(result)

        if log.get("nextToken"):
            next_token = log["nextToken"]
        else:
            print(cnt) #총 개수 출력
            break
    
    ret = json.dumps({"total" : cnt, "totalNotFiltered" : cnt, "rows" : output})
    response = s3.put_object(Body=ret,
                            Bucket='threatitem',
                            Key='IAM/13' )
    return response
    
# 7. 컴퓨팅 리소스 시작
def ComputingResource():
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='{$.eventSource = "iam.amazonaws.com" && $.eventName="RunInstances"}',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='{$.eventSource = "iam.amazonaws.com" && $.eventName="RunInstances"}'
            )
        for i in log['events']:
            result = {"id" : cnt, "timestamp": datetime.datetime.fromtimestamp(i['timestamp']/1000).strftime('%Y-%m-%d %H:%M:%S'), "message": i['message']}
            cnt += 1
            output.append(result)

        if log.get("nextToken"):
            next_token = log["nextToken"]
        else:
            print(cnt) #총 개수 출력
            break
    
    ret = json.dumps({"total" : cnt, "totalNotFiltered" : cnt, "rows" : output})
    response = s3.put_object(Body=ret,
                            Bucket='threatitem',
                            Key='IAM/14' )
    return response
    

   