import boto3
import time
import json
import datetime


AWS_ACCESS_KEY_ID = ""
AWS_SECRET_ACCESS_KEY = ""
AWS_DEFAULT_REGION = "ap-northeast-2"


logs = boto3.client('logs',
                aws_access_key_id=AWS_ACCESS_KEY_ID,
                      aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                      region_name=AWS_DEFAULT_REGION)

s3 = boto3.client('s3',aws_access_key_id=AWS_ACCESS_KEY_ID,
                      aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                      region_name=AWS_DEFAULT_REGION)


# 버킷 목록 검색 (10초)
def List_Objects():
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='{$.eventName="ListObjects"}',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='{$.eventName="ListObjects"}'
            )
        for i in log['events']:
            msg_json = json.loads(i.get('message'))
            if 's3.amazonaws.com' in msg_json['eventSource']:
                
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
                            Key='S3/0' )
    return response


# S3 데이터 생성 (2분)
def S3_Create_Data():
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='{$.eventName="PutObject"}',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='{$.eventName="PutObject"}'
            )
        for i in log['events']:
            msg_json = json.loads(i.get('message'))
            if 's3.amazonaws.com' in msg_json['eventSource']:
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
                            Key='S3/1' )
    return response


# S3 데이터 삭제 (10초 내)
def S3_Delete_Data():
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='{$.eventName="DeleteObjects"}',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='{$.eventName="DeleteObjects"}'
            )
        for i in log['events']:
            msg_json = json.loads(i.get('message'))
            if 's3.amazonaws.com' in msg_json['eventSource']:
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
                            Key='S3/2' )
    return response


# 비정상적 IAM 개체의 S3 API 호출 ListBuckets & "errorCode":"AccessDenied"
def Call_API_Abnormal_Object():
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='{$.eventName="ListBuckets"}',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='{$.eventName="ListBuckets"}'
            )
        for i in log['events']:
            msg_json = json.loads(i.get('message'))
            if 's3.amazonaws.com' in msg_json['eventSource']:
                if '"errorCode":"AccessDenied"' in i['message']:
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
                            Key='S3/3' )
    return response


# 서버 액세스 로깅 비활성화
def Access_Logging_Disabled():
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='{$.eventName="GetBucketPublicAccessBlock"}',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='{$.eventName="GetBucketPublicAccessBlock"}'
            )
        for i in log['events']:
            msg_json = json.loads(i.get('message'))
            if 's3.amazonaws.com' in msg_json['eventSource']:
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
                            Key='S3/4' )
    return response


# 버킷 또는 객체의 권한 변경
def Modify_Policy_BucketObject():
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='{$.eventName="PutBucketAcl"}',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='{$.eventName="PutBucketAcl"}'
            )
        for i in log['events']:
            msg_json = json.loads(i.get('message'))
            if 's3.amazonaws.com' in msg_json['eventSource']:
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
                            Key='S3/5' )
    return response


# 버킷 정책 변경
def Modify_Bucket_Policy():
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='{$.eventName="PutBucketPolicy"}',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='{$.eventName="PutBucketPolicy"}'
            )
        for i in log['events']:
            msg_json = json.loads(i.get('message'))
            if 's3.amazonaws.com' in msg_json['eventSource']:
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
                            Key='S3/6' )
    return response


# 특정 linux 시스템에서의 접근
def Access_System():
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='{$.userAgent="-kali" || $.userAgent="parrot - WebIdentityUser" || $.userAgent="pentoo"}',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='{$.userAgent="-kali" || $.userAgent="parrot - WebIdentityUser" || $.userAgent="pentoo"}'
            )
        for i in log['events']:
            if 's3.amazonaws.com' in i['message']:
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
                            Key='S3/7' )
    
    return response

