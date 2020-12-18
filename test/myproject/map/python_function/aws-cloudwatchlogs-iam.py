import boto3
import json

#AWS_ACCESS_KEY_ID = "yourkey"  # your key
#AWS_SECRET_ACCESS_KEY = "yourkey"  # your key
#AWS_DEFAULT_REGION = "ap-northeast-2"

logs = boto3.client('logs',
                    aws_access_key_id=AWS_ACCESS_KEY_ID,
                    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                    region_name=AWS_DEFAULT_REGION)

# 1. 특이한 리전에 인프라 생성 및 배포, API 호출

# 2. 침투 테스트 시스템에서 API 호출
def PentestSystems():
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
            if 'iam.amazonaws.com' in i.get('message'):
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

# 3. 네트워크 액세스 권한 변경(보안 그룹, 라우트, ACL)
def NetworkPermissions():
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='CreateSecurityGroup',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='CreateSecurityGroup'
            )
        for i in log['events']:
            if 'iam.amazonaws.com' in i.get('message'):
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

# 4. CloudTrail 추적 비활성화
# def CloudTrailLoggingDisabled():


# 5. CloudTrail로깅 중단, 기존 로그 삭제 => API = StopLogging
def LoggingConfigurationModified():
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='StopLogging',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='StopLogging'
            )
        for i in log['events']:
            if 'iam.amazonaws.com' in i.get('message'):
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

# 6. IAM 사용자, 그룹 또는 정책을 추가/변경/삭제
def UserPermissions():
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='?AttachUserPolicy ?ListInstanceProfilesForRole',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='?AttachUserPolicy ?ListInstanceProfilesForRole'
            )
        for i in log['events']:
            if 'iam.amazonaws.com' in i.get('message'):
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

# 7. 리소스 보안 액세스 정책 변경
def ResourcePermissions():
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
            if 'iam.amazonaws.com' in i.get('message'):
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

# 8. 루트 계정
def RootCredentialUsage():
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='root',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='root'
            )
        for i in log['events']:
            if 'iam.amazonaws.com' in i.get('message'):
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

# 9. 계정 암호 정책 약화
# def PasswordPolicyChange():

# 10. 비정상적인 콘솔 로그인
# def ConsoleLoginDetect():

# 11. 컴퓨팅 리소스 시작
def ComputingResource():
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='RunInstances',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='RunInstances'
            )
        for i in log['events']:
            if 'iam.amazonaws.com' in i.get('message'):
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

# 함수 실행
# PentestSystems()        #2
# NetworkPermissions()    #3
# LoggingConfigurationModified()  #5
# UserPermissions()       #6
# ResourcePermissions()   #7
# RootCredentialUsage()   #8
# ComputingResource()     #11
