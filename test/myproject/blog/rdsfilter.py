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


# DB 목록 검색
def DescribeDBInstances():
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='{$.eventSource = "rds.amazonaws.com" && $.eventName="DescribeDBInstances"}',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='{$.eventSource = "rds.amazonaws.com" && $.eventName="DescribeDBInstances"}'
            )
        for i in log['events']:
            result = {"id" : cnt, "timestamp": datetime.datetime.fromtimestamp(i['timestamp']/1000).strftime('%Y-%m-%d %H:%M:%S'), "message": i['message']}
            cnt += 1
            output.append(result)

        if log.get("nextToken"):
            next_token = log["nextToken"]
        else:
            print(cnt)
            break
    
    ret = json.dumps({"total" : cnt, "totalNotFiltered" : cnt, "rows" : output})
    response = s3.put_object(Body=ret,
                            Bucket='threatitem',
                            Key='RDS/15' )
    return response

# DB 내의 데이터 삭제
def DeleteDBData():
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='/aws/rds/instance/database-2/general',
                filterPattern='?DELETE ?delete ?DROP',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='/aws/rds/instance/database-2/general',
                filterPattern='?DELETE ?delete ?DROP'
            )
        for i in log['events']:
            if u'innodb_txn_key' not in i['message']:
                result = {"id" : cnt, "timestamp": datetime.datetime.fromtimestamp(i['timestamp']/1000).strftime('%Y-%m-%d %H:%M:%S'), "message": i['message']}
                cnt += 1
                output.append(result)

        if log.get("nextToken"):
            next_token = log["nextToken"]
        else:
            print(cnt)
            break
    
    ret = json.dumps({"total" : cnt, "totalNotFiltered" : cnt, "rows" : output})
    response = s3.put_object(Body=ret,
                            Bucket='threatitem',
                            Key='RDS/16' )
    return response

# DB 사용자 추가
def AddUser():
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='/aws/rds/instance/database-2/general',
                filterPattern='CREATE USER',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='/aws/rds/instance/database-2/general',
                filterPattern='CREATE USER'
            )
        for i in log['events']:
            result = {"id" : cnt, "timestamp": datetime.datetime.fromtimestamp(i['timestamp']/1000).strftime('%Y-%m-%d %H:%M:%S'), "message": i['message']}
            cnt += 1
            output.append(result)

        if log.get("nextToken"):
            next_token = log["nextToken"]
        else:
            print(cnt)
            break
    
    ret = json.dumps({"total" : cnt, "totalNotFiltered" : cnt, "rows" : output})
    response = s3.put_object(Body=ret,
                            Bucket='threatitem',
                            Key='RDS/17' )
    return response

# DB 사용자 권한 수정
def GrantAuth():
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='/aws/rds/instance/database-2/general',
                filterPattern='GRANT',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='/aws/rds/instance/database-2/general',
                filterPattern='GRANT'
            )
        for i in log['events']:
            result = {"id" : cnt, "timestamp": datetime.datetime.fromtimestamp(i['timestamp']/1000).strftime('%Y-%m-%d %H:%M:%S'), "message": i['message']}
            cnt += 1
            output.append(result)

        if log.get("nextToken"):
            next_token = log["nextToken"]
        else:
            print(cnt)
            break
    
    ret = json.dumps({"total" : cnt, "totalNotFiltered" : cnt, "rows" : output})
    response = s3.put_object(Body=ret,
                            Bucket='threatitem',
                            Key='RDS/18' )
    return response

# RDS 관련 API call
def RDSAPICall():
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='{$.eventSource = "rds.amazonaws.com" && $.eventName="=DescribeDBInstances"}',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='{$.eventSource = "rds.amazonaws.com" && $.eventName="=DescribeDBInstances"}'
            )
        for i in log['events']:
            msg_json = json.loads(i.get('message'))
            if 'rds.amazonaws.com' in msg_json['eventSource']:
                if '"errorCode":"AccessDenied"' in i['message']:
                    result = {"id" : cnt, "timestamp": datetime.datetime.fromtimestamp(i['timestamp']/1000).strftime('%Y-%m-%d %H:%M:%S'), "message": i['message']}
                    cnt += 1
                    output.append(result)

        if log.get("nextToken"):
            next_token = log["nextToken"]
        else:
            print(cnt)
            break
    
    ret = json.dumps({"total" : cnt, "totalNotFiltered" : cnt, "rows" : output})
    response = s3.put_object(Body=ret,
                            Bucket='threatitem',
                            Key='RDS/19' )
    return response

# 로깅 관련 파라미터 그룹 수정 + nextToken
def ModifyDBParameterGroup():
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='{$.eventSource = "rds.amazonaws.com" && ($.eventName="ModifyDBParameterGroup" || $.eventName="ResetDBParameterGroup")}',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='{$.eventSource = "rds.amazonaws.com" && ($.eventName="ModifyDBParameterGroup" || $.eventName="ResetDBParameterGroup")}'
            )
        for i in log['events']:
            temp = str(i['message'])
            if 'general_log' in temp:
                if temp[temp.index('general_log') + 31:temp.index('general_log') + 32] != '1':
                    result = {"id" : cnt, "timestamp": datetime.datetime.fromtimestamp(i['timestamp']/1000).strftime('%Y-%m-%d %H:%M:%S'), "message": i['message']}
                    cnt += 1
                    output.append(result)
            elif 'slow_query_log' in temp:
                if temp[temp.index('slow_query_log') + 34:temp.index('slow_query_log') + 35] != '1':
                    result = {"id" : cnt, "timestamp": datetime.datetime.fromtimestamp(i['timestamp']/1000).strftime('%Y-%m-%d %H:%M:%S'), "message": i['message']}
                    cnt += 1
                    output.append(result)
            elif 'log_output' in temp:
                if temp[temp.index('log_output') + 30:temp.index('log_output') + 34] != 'FILE':
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
                            Key='RDS/20' )
    return response

# 로깅 관련 파라미터 그룺 삭제
def DeleteDBParameterGroup():
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='{$.eventSource = "rds.amazonaws.com" && $.eventName="DeleteDBParameterGroup"}',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='{$.eventSource = "rds.amazonaws.com" && $.eventName="DeleteDBParameterGroup"}'
            )
        for i in log['events']:
            result = {"id" : cnt, "timestamp": datetime.datetime.fromtimestamp(i['timestamp']/1000).strftime('%Y-%m-%d %H:%M:%S'), "message": i['message']}
            cnt += 1
            output.append(result)
                


        if log.get("nextToken"):
            next_token = log["nextToken"]
        else:
            print(cnt)
            break
    
    ret = json.dumps({"total" : cnt, "totalNotFiltered" : cnt, "rows" : output})
    response = s3.put_object(Body=ret,
                            Bucket='threatitem',
                            Key='RDS/21' )
    return response

# DB 중지
def StopDBInstance():
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='{$.eventSource = "rds.amazonaws.com" && $.eventName="StopDBInstance"}',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='{$.eventSource = "rds.amazonaws.com" && $.eventName="StopDBInstance"}'
            )
        for i in log['events']:
            result = {"id" : cnt, "timestamp": datetime.datetime.fromtimestamp(i['timestamp']/1000).strftime('%Y-%m-%d %H:%M:%S'), "message": i['message']}
            cnt += 1
            output.append(result)
                

        jsonoutput = json.dumps(output)

        if log.get("nextToken"):
            next_token = log["nextToken"]
        else:
            print(cnt)
            break
    
    ret = json.dumps({"total" : cnt, "totalNotFiltered" : cnt, "rows" : output})
    response = s3.put_object(Body=ret,
                            Bucket='threatitem',
                            Key='RDS/22' )
    return response

# DB 삭제
def DeleteDBInstance():
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='{$.eventSource = "rds.amazonaws.com" && $.eventName="DeleteDBInstance"}',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='{$.eventSource = "rds.amazonaws.com" && $.eventName="DeleteDBInstance"}'
            )
        for i in log['events']:
            result = {"id" : cnt, "timestamp": datetime.datetime.fromtimestamp(i['timestamp']/1000).strftime('%Y-%m-%d %H:%M:%S'), "message": i['message']}
            cnt += 1
            output.append(result)
                
     

        if log.get("nextToken"):
            next_token = log["nextToken"]
        else:
            print(cnt)
            break
    
    ret = json.dumps({"total" : cnt, "totalNotFiltered" : cnt, "rows" : output})
    response = s3.put_object(Body=ret,
                            Bucket='threatitem',
                            Key='RDS/23' )
    return response

# 위험가능성 있는 OS에서의 API call
def SusOSAPI():
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='{ $.eventSource = "rds.amazonaws.com" && ($.userAgent="*kali*" || $.userAgent="*parrot*" || $.userAgent="*pentoo*")}',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='{ $.eventSource = "rds.amazonaws.com" && ($.userAgent="*kali*" || $.userAgent="*parrot*" || $.userAgent="*pentoo*")}'
            )
        for i in log['events']:
            result = {"id" : cnt, "timestamp": datetime.datetime.fromtimestamp(i['timestamp']/1000).strftime('%Y-%m-%d %H:%M:%S'), "message": i['message']}
            cnt += 1
            output.append(result)

        if log.get("nextToken"):
            next_token = log["nextToken"]
        else:
            print(cnt)
            break
    
    ret = json.dumps({"total" : cnt, "totalNotFiltered" : cnt, "rows" : output})
    response = s3.put_object(Body=ret,
                            Bucket='threatitem',
                            Key='RDS/24' )
    return response

# cloudwatch 로깅 수정
def StopWatchLogs():
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='{$.eventSource = "rds.amazonaws.com" && $.eventName="ModifyDBInstance"}',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='{$.eventSource = "rds.amazonaws.com" && $.eventName="ModifyDBInstance"}'
            )
        for i in log['events']:
            temp = str(i['message'])
            if 'disableLogTypes' in temp:
                if temp[temp.index('disableLogTypes') + 17:temp.index('disableLogTypes') + 19] != "[]":
                    result = {"id" : cnt, "timestamp": datetime.datetime.fromtimestamp(i['timestamp']/1000).strftime('%Y-%m-%d %H:%M:%S'), "message": i['message']}
                    cnt += 1
                    output.append(result)

        if log.get("nextToken"):
            next_token = log["nextToken"]
        else:
            print(cnt)
            break
    
    ret = json.dumps({"total" : cnt, "totalNotFiltered" : cnt, "rows" : output})
    response = s3.put_object(Body=ret,
                            Bucket='threatitem',
                            Key='RDS/25' )
    return response

# DB 접속 실패 기록
def RDSAccessDenied():
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='/aws/rds/instance/database-2/general',
                filterPattern='Connect Access denied',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='/aws/rds/instance/database-2/general',
                filterPattern='Connect Access denied'
            )
        for i in log['events']:
            result = {"id" : cnt, "timestamp": datetime.datetime.fromtimestamp(i['timestamp']/1000).strftime('%Y-%m-%d %H:%M:%S'), "message": i['message']}
            cnt += 1
            output.append(result)

        if log.get("nextToken"):
            next_token = log["nextToken"]
        else:
            print(cnt)
            break
    
    ret = json.dumps({"total" : cnt, "totalNotFiltered" : cnt, "rows" : output})
    response = s3.put_object(Body=ret,
                            Bucket='threatitem',
                            Key='RDS/26' )
    return response

