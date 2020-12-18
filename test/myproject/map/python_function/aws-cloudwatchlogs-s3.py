import boto3
import time
import json

AWS_ACCESS_KEY_ID = "KEY_VALUE"
AWS_SECRET_ACCESS_KEY = "SECRET_KEY_VALUE"
AWS_DEFAULT_REGION = "REGION"

start = time.time()
logs = boto3.client('logs',
                aws_access_key_id=AWS_ACCESS_KEY_ID,
                      aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                      region_name=AWS_DEFAULT_REGION)

# 버킷 목록 검색
def List_Objects():
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='ListObjects',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='ListObjects'
            )
        for i in log['events']:
            if 's3.amazonaws.com' in i['message']:
                cnt += 1
                result = {"timestamp": i['timestamp'], "message": i['message']}
                output.append(result)
                print(result)
                print(cnt)
        jsonoutput = json.dumps(output)

        if log.get("nextToken"):
            next_token = log["nextToken"]
        else:
            break
    return jsonoutput

# S3 데이터 생성, 삭제 -> 보완
def S3_Data():
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='PutObject?DeleteObjects',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='PutObject?DeleteObjects'
            )
        for i in log['events']:
            if 's3.amazonaws.com' in i['message']:
                cnt += 1
                result = {"timestamp": i['timestamp'], "message": i['message']}
                output.append(result)
                print(result)
                print(cnt)

        jsonoutput = json.dumps(output)

        if log.get("nextToken"):
            next_token = log["nextToken"]
        else:
            break
    return jsonoutput

# 비정상적 IAM 개체의 S3 API 호출 ListBuckets & "errorCode":"AccessDenied" -> 보완
def Call_API_Abnormal_Object():
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='ListBuckets',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='ListBuckets'
            )
        for i in log['events']:
            if 's3.amazonaws.com' in i['message']:
                if '"errorCode":"AccessDenied"' in i['message']:
                    cnt += 1
                    result = {"timestamp": i['timestamp'], "message": i['message']}
                    output.append(result)
                    print(result)
                    print(cnt)
        jsonoutput = json.dumps(output)

        if log.get("nextToken"):
            next_token = log["nextToken"]
        else:
            break
    return jsonoutput

# 서버 액세스 로깅 비활성화
def Access_Logging_Disabled():
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='GetBucketPublicAccessBlock',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='GetBucketPublicAccessBlock'
            )
        for i in log['events']:
            if 's3.amazonaws.com' in i['message']:
                cnt += 1
                result = {"timestamp": i['timestamp'], "message": i['message']}
                output.append(result)
                print(result)
                print(cnt)
        jsonoutput = json.dumps(output)

        if log.get("nextToken"):
            next_token = log["nextToken"]
        else:
            break
    return jsonoutput

# 버킷 또는 객체의 권한 변경
def Modify_Policy_BucketObject():
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='PutBucketAcl',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='PutBucketAcl'
            )
        for i in log['events']:
            if 's3.amazonaws.com' in i['message']:
                cnt += 1
                result = {"timestamp": i['timestamp'], "message": i['message']}
                output.append(result)
                print(result)
                print(cnt)
        jsonoutput = json.dumps(output)

        if log.get("nextToken"):
            next_token = log["nextToken"]
        else:
            break
    return jsonoutput

# 버킷 정책 변경
def Modify_Bucket_Policy():
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='PutBucketPolicy',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='PutBucketPolicy'
            )
        for i in log['events']:
            if 's3.amazonaws.com' in i['message']:
                cnt += 1
                result = {"timestamp": i['timestamp'], "message": i['message']}
                output.append(result)
                print(result)
                print(cnt)
        jsonoutput = json.dumps(output)

        if log.get("nextToken"):
            next_token = log["nextToken"]
        else:
            break
    return jsonoutput

# 특정 linux 시스템에서의 접근 kali
def Access_System():
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='?"-kali" ?"parrot - WebIdentityUser" ?pentoo',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='?"-kali" ?"parrot - WebIdentityUser" ?pentoo'
            )
        for i in log['events']:
            if 's3.amazonaws.com' in i['message']:
                cnt += 1
                result = {"timestamp": i['timestamp'], "message": i['message']}
                output.append(result)
                print(result)
                print(cnt)
        jsonoutput = json.dumps(output)

        if log.get("nextToken"):
            next_token = log["nextToken"]
        else:
            break
    return jsonoutput

# 버킷 목록 검색
List_Objects()
# S3 데이터 생성, 삭제
#S3_Data()
# 비정상적 IAM 개체의 S3 API 호출
#Call_API_Abnormal_Object()
# 서버 액세스 로깅 비활성화
#Access_Logging_Disabled()
# 버킷 또는 객체의 권한 변경
#Modify_Policy_BucketObject()
# 버킷 정책 변경
#Modify_Bucket_Policy()
# 특정 linux 시스템에서의 접근
#Access_System()
print("time :", time.time() - start)
