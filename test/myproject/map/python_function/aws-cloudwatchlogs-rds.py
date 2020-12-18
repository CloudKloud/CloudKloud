import boto3
import json

AWS_ACCESS_KEY_ID = "KEY_VALUE"
AWS_SECRET_ACCESS_KEY = "SECRET_KEY_VALUE"
AWS_DEFAULT_REGION = "REGION"

logs = boto3.client('logs', aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
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
                filterPattern='DescribeDBInstances',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='DescribeDBInstances'
            )
        for i in log['events']:
            if 'rds.amazonaws.com' in i['message']:
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
            if 'rds.amazonaws.com' in i['message']:
                if u'innodb_txn_key' not in i['message']:
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
            if 'rds.amazonaws.com' in i['message']:
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
            if 'rds.amazonaws.com' in i['message']:
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

# RDS 관련 API call
def RDSAPICall():
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail'
            )
        for i in log['events']:
            if 'rds.amazonaws.com' in i['message']:
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

# 로깅 관련 파라미터 그룹 수정 + nextToken
def ModifyDBParameterGroup():
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='ModifyDBParameterGroup',
                nextToken=next_token
            )
            log2 = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='ResetDBParameterGroup',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='ModifyDBParameterGroup'
            )
            log2 = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='ResetDBParameterGroup'
            )
        for i in log['events']:
            if 'rds.amazonaws.com' in i['message']:
                temp = str(i['message'])
                if 'general_log' in temp:
                    if temp[temp.index('general_log') + 31:temp.index('general_log') + 32] != '1':
                        line = {"timestamp": i['timestamp'], "message": i['message']}
                        output.append(line)
                        cnt += 1
                        print(line)
                        print(cnt)
                elif 'slow_query_log' in temp:
                    if temp[temp.index('slow_query_log') + 34:temp.index('slow_query_log') + 35] != '1':
                        line = {"timestamp": i['timestamp'], "message": i['message']}
                        output.append(line)
                        cnt += 1
                        print(line)
                        print(cnt)
                elif 'log_output' in temp:
                    if temp[temp.index('log_output') + 30:temp.index('log_output') + 34] != 'FILE':
                        line = {"timestamp": i['timestamp'], "message": i['message']}
                        output.append(line)
                        cnt += 1
                        print(line)
                        print(cnt)
        for j in log2['events']:
            if 'rds.amazonaws.com' in j['message']:
                cnt += 1
                result = {"timestamp": j['timestamp'], "message": j['message']}
                output.append(result)
                print(result)
                print(cnt)

        output = sorted(output, key=(lambda x: x["timestamp"]))

        if log.get("nextToken"):
            next_token = log["nextToken"]
        elif log2.get("nextToken"):
            next_token = log2["nextToken"]
        else:
            break
    return json.dumps(output)

# 로깅 관련 파라미터 그룺 삭제
def DeleteDBParameterGroup():
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='DeleteDBParameterGroup',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='DeleteDBParameterGroup'
            )
        for i in log['events']:
            if 'rds.amazonaws.com' in i['message']:
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

# DB 중지
def StopDBInstance():
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='StopDBInstance',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='StopDBInstance'
            )
        for i in log['events']:
            if 'rds.amazonaws.com' in i['message']:
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

# DB 삭제
def DeleteDBInstance():
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='DeleteDBInstance',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='DeleteDBInstance'
            )
        for i in log['events']:
            if 'rds.amazonaws.com' in i['message']:
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

# 위험가능성 있는 OS에서의 API call
def SusOSAPI():
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
            if 'rds.amazonaws.com' in i['message']:
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

# cloudwatch 로깅 수정
def StopWatchLogs():
    cnt = 0
    output = []
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='ModifyDBInstance',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                filterPattern='ModifyDBInstance'
            )
        for i in log['events']:
            if 'rds.amazonaws.com' in i['message']:
                temp = str(i['message'])
                if 'disableLogTypes' in temp:
                    if temp[temp.index('disableLogTypes') + 17:temp.index('disableLogTypes') + 19] != "[]":
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
            if 'rds.amazonaws.com' in i['message']:
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


# DescribeDBInstances()
# DeleteDBData()
# AddUser()
# GrantAuth()
# RDSAPICall()
ModifyDBParameterGroup()    #
# DeleteDBParameterGroup()
# StopDBInstance()
# DeleteDBInstance()
# SusOSAPI()
# StopWatchLogs()
# RDSAccessDenied()
