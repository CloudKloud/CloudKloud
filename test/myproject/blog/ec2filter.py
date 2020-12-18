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
ssm_client = boto3.client('ssm',
                      aws_access_key_id=AWS_ACCESS_KEY_ID,
                      aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                      region_name=AWS_DEFAULT_REGION
                      )  

s3 = boto3.client('s3',aws_access_key_id=AWS_ACCESS_KEY_ID,
                      aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                      region_name=AWS_DEFAULT_REGION)


def ShellCMDyum(): # 패키지매니저 관련 명령어 로그
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='cb-test-api-cmd',
                filterPattern='"add user"',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='cb-test-api-cmd',
                filterPattern='"add user"'
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
                            Key='EC2/27' )
    return response


def ShellCMDsudo(): # 루트권한 호출 관련 명령어 로그
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='cb-test-api-cmd',
                filterPattern='?"sudo "',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='cb-test-api-cmd',
                filterPattern='?"sudo "'
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
                            Key='EC2/28' )
    return response


def ShellCMDservice(): # 서비스 동작 관련 명령어 로그
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='cb-test-api-cmd',
                filterPattern='?"service "',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='cb-test-api-cmd',
                filterPattern='?"service "'
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
                            Key='EC2/29' )
    return response


def ShellCMDcron(): # cron 관련 명령어 로그
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='cb-test-api-cmd',
                filterPattern='?"cron "',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='cb-test-api-cmd',
                filterPattern='?"cron "'
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
                            Key='EC2/30' )
    return response



def VPCFLOWreject(): # REJECT된 통신 기록
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='VPC-flow',
                filterPattern='?"REJECT "' ,
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='VPC-flow',
                filterPattern='?"REJECT "'
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
                            Key='EC2/31' )
    return response


def CreateInstances():
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='{$.eventSource = "ec2.amazonaws.com" && $.eventName="RunInstances" && $.userIdentity.userName!="kyungsillee"}',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='{$.eventSource = "ec2.amazonaws.com" && $.eventName="RunInstances" && $.userIdentity.userName!="kyungsillee"}',
            )
        for i in log['events']:
            result = {"id" : cnt, "timestamp": i['timestamp'], "message": i['message']}
            cnt += 1
            output.append(result)

        if log.get("nextToken"):
            next_token = log["nextToken"]
        else:
            break

    for i in range(len(output)):
        output[i]['timestamp'] = datetime.datetime.fromtimestamp(output[i]['timestamp']/1000).strftime('%Y-%m-%d %H:%M:%S')
 

    ret = json.dumps({"total" : cnt, "totalNotFiltered" : cnt, "rows" : output})
    response = s3.put_object(Body=ret,
                            Bucket='threatitem',
                            Key='EC2/32' )
    return response


def DeleteInstances():
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='{$.eventSource = "ec2.amazonaws.com" && $.eventName="StopInstances"}',
                nextToken=next_token
            )
            log2 = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='{$.eventSource = "ec2.amazonaws.com" && $.eventName="TermibateInstances"}',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='{$.eventSource = "ec2.amazonaws.com" && $.eventName="StopInstances"}',
            )
            log2 = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='{$.eventSource = "ec2.amazonaws.com" && $.eventName="TermibateInstances"}',
            )
        for i in log['events']:
            result = {"id" : cnt, "timestamp": i['timestamp'], "message": i['message']}
            cnt += 1
            output.append(result)

        for j in log2['events']:
            result = {"id" : cnt, "timestamp": j['timestamp'], "message": j['message']}
            cnt += 1
            output.append(result)
        
        if log.get("nextToken"):
            next_token = log["nextToken"]
        elif log2.get("nextToken"):
            next_token = log2["nextToken"]
        else:
            break
    output = sorted(output, key=(lambda x: x["timestamp"]))

    for i in range(len(output)):
        output[i]['timestamp'] = datetime.datetime.fromtimestamp(output[i]['timestamp']/1000).strftime('%Y-%m-%d %H:%M:%S')
   

    ret = json.dumps({"total" : cnt, "totalNotFiltered" : cnt, "rows" : output})
    response = s3.put_object(Body=ret,
                            Bucket='threatitem',
                            Key='EC2/33' )
    return response


def ModifySecurityGroupRule():
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='AuthorizeSecurityGroupEgress',
                nextToken=next_token
            )
            log2 = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='AuthorizeSecurityGroupIngress',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='AuthorizeSecurityGroupEgress',
            )
            log2 = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='AuthorizeSecurityGroupIngress'
            )
        for i in log['events']:
            result = {"id" : cnt, "timestamp": i['timestamp'], "message": i['message']}
            cnt += 1
            output.append(result)
        for j in log2['events']:
            result = {"id" : cnt, "timestamp": j['timestamp'], "message": j['message']}
            cnt += 1
            output.append(result)

        if log.get("nextToken"):
            next_token = log["nextToken"]
        elif log2.get("nextToken"):
            next_token = log2["nextToken"]
        else:
            break
    output = sorted(output, key=(lambda x: x["timestamp"]))

    for i in range(len(output)):
        output[i]['timestamp'] = datetime.datetime.fromtimestamp(output[i]['timestamp']/1000).strftime('%Y-%m-%d %H:%M:%S')
    

    ret = json.dumps({"total" : cnt, "totalNotFiltered" : cnt, "rows" : output})
    response = s3.put_object(Body=ret,
                            Bucket='threatitem',
                            Key='EC2/34' )
    return response

def PentestSystems():
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='{ $.eventSource = "ec2.amazonaws.com" && ($.userAgent="*kali*" || $.userAgent="*parrot*" || $.userAgent="*pentoo*")}',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='{ $.eventSource = "ec2.amazonaws.com" && ($.userAgent="*kali*" || $.userAgent="*parrot*" || $.userAgent="*pentoo*")}'
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
                            Key='EC2/35' )
    return response
