import boto3
import json
import time
from datetime import datetime
nowtime = datetime.now()

AWS_ACCESS_KEY_ID =""
AWS_SECRET_ACCESS_KEY = ""
AWS_DEFAULT_REGION = "ap-northeast-2"
# 이건 VPC Flow 틀어놓은 개인계정

logs = boto3.client('logs', aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                    region_name=AWS_DEFAULT_REGION)
ec2 = boto3.resource('ec2',
                      aws_access_key_id=AWS_ACCESS_KEY_ID,
                      aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                      region_name=AWS_DEFAULT_REGION
                      )    
ssm_client = boto3.client('ssm',
                      aws_access_key_id=AWS_ACCESS_KEY_ID,
                      aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                      region_name=AWS_DEFAULT_REGION
                      )                

'''
비정상적 포트로 통신
25번 포트로 통신 (Spam bot)
알려진 malicious IP와의 통신
대량의 트래픽 발생 (DOS)
네트워크 스캐닝
IP 기반 접근제어 부재
의심스런 도메인과의 통신
사용하지 않는 프로토콜 사용
인스턴스 시작/종료 시점
'''

'''
최종 결과 형식
result = {"timestamp": i['timestamp'], "message": i['message']}
print(result)
'''

print("== EC2 인스턴스 목록 ==")
for instance in ec2.instances.all():
    nowtime = datetime.now()
    result = {"timestamp": "%s-%s-%sT%s:%s:%s.%sZ" %(nowtime.year, nowtime.month, nowtime.day, nowtime.hour, nowtime.minute, nowtime.second, str(nowtime.microsecond)[0:2]), "message": instance.id}
    print(result)
print("== 실행 중인 EC2 인스턴스 목록 ==")
for instance in ec2.instances.all():
    if instance.state['Name'] == 'running':
        result = {"timestamp": "%s-%s-%sT%s:%s:%s.%sZ" %(nowtime.year, nowtime.month, nowtime.day, nowtime.hour, nowtime.minute, nowtime.second, str(nowtime.microsecond)[0:2]), "message": instance.id}
        print(result)
print("== 일시 정지 중인 EC2 인스턴스 목록 ==")
for instance in ec2.instances.all():
    if instance.state['Name'] == 'stopped':
        result = {"timestamp": "%s-%s-%sT%s:%s:%s.%sZ" %(nowtime.year, nowtime.month, nowtime.day, nowtime.hour, nowtime.minute, nowtime.second, str(nowtime.microsecond)[0:2]), "message": instance.id}
        print(result)

target_id = "i-0809bd00775331efb"

print("== 전체 보안 그룹명 ==")
sgs = list(ec2.security_groups.all())
all_sgs = set([sg.group_name for sg in sgs])
result = {"timestamp": "%s-%s-%sT%s:%s:%s.%sZ" %(nowtime.year, nowtime.month, nowtime.day, nowtime.hour, nowtime.minute, nowtime.second, str(nowtime.microsecond)[0:2]), "message": all_sgs}
print(result)

response = ssm_client.send_command(
            InstanceIds=[
                target_id 
                    ],
            DocumentName="AWS-RunShellScript",
            Comment="Code to run" ,
            Parameters={
                    "commands": ["uname -a"]
                        }
            )
cmd_id= response['Command']['CommandId']
time.sleep(2)                                                   # 이거 안하면 get_command_invocation에서 에러 뿜뿜함
response = ssm_client.get_command_invocation(CommandId=cmd_id, 
InstanceId=target_id)
print("== 시스템 정보 ==")    
result = {"timestamp":response['ExecutionStartDateTime'] , "message":response['StandardOutputContent']}                                  
print(result)

response = ssm_client.send_command(
            InstanceIds=[
                target_id 
                    ],
            DocumentName="AWS-RunShellScript",
            Comment="Code to run" ,
            Parameters={
                    "commands": ["netstat -tnl | tail -n+2"]
                        }
            )
cmd_id= response['Command']['CommandId']
time.sleep(2)                                                             
response = ssm_client.get_command_invocation(CommandId=cmd_id, 
InstanceId=target_id) 
print("== 포트 연결 현황 ==")                                              
result = {"timestamp":response['ExecutionStartDateTime'] , "message":response['StandardOutputContent']}                                  
print(result) 

response = ssm_client.send_command(
            InstanceIds=[
                target_id 
                    ],
            DocumentName="AWS-RunShellScript",
            Comment="Code to run" ,
            Parameters={
                    "commands": ["netstat -tnl | tail -n+2"]
                        }
            )
cmd_id= response['Command']['CommandId']
time.sleep(2)                                                             
response = ssm_client.get_command_invocation(CommandId=cmd_id, 
InstanceId=target_id) 
print("== 활성화된 포트 리스트 ==")                                              
ContentsAsList = response['StandardOutputContent'].split(" ")
ports = []
for contents in ContentsAsList:
    if ":" in contents:
        ports.append(contents)
for place in ports:
    result = {"timestamp":response['ExecutionStartDateTime'] , "message":place[place.find(":")+1::]} 
    print(result)

response = ssm_client.send_command(
            InstanceIds=[
                target_id 
                    ],
            DocumentName="AWS-RunShellScript",
            Comment="Code to run" ,
            Parameters={
                    "commands": ["last"]
                        }
            )
cmd_id= response['Command']['CommandId']
time.sleep(2)                                                 
response = ssm_client.get_command_invocation(CommandId=cmd_id, 
InstanceId=target_id) 
print("== 쉘 접속자 현황 ==")                                            
result = {"timestamp":response['ExecutionStartDateTime'] , "message":response['StandardOutputContent']}                                  
print(result)

response = ssm_client.send_command(
            InstanceIds=[
                target_id 
                    ],
            DocumentName="AWS-RunShellScript",
            Comment="Code to run" ,
            Parameters={
                    "commands": ["curl bot.whatismyipaddress.com"]
                        }
            )
cmd_id= response['Command']['CommandId']
time.sleep(2)                                                 
response = ssm_client.get_command_invocation(CommandId=cmd_id, 
InstanceId=target_id) 
print("== 퍼블릭 아이피 주소 ==")                                            
result = {"timestamp":response['ExecutionStartDateTime'] , "message":response['StandardOutputContent']}                                  
print(result)

response = ssm_client.send_command(
            InstanceIds=[
                target_id 
                    ],
            DocumentName="AWS-RunShellScript",
            Comment="Code to run" ,
            Parameters={
                    "commands": ["last | grep 'reboot'"]
                        }
            )
cmd_id= response['Command']['CommandId']
time.sleep(2)                                                 
response = ssm_client.get_command_invocation(CommandId=cmd_id, 
InstanceId=target_id) 
print("== 재부팅 로그 ==")                                            
result = {"timestamp":response['ExecutionStartDateTime'] , "message":response['StandardOutputContent']}                                  
print(result)


srciptotal = dict()
def IPcommLogs():
    cnt = 0
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='VPC-flow',
                filterPattern='',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='VPC-flow',
                filterPattern=''
            )
        

    # 해당 로그 기반으로 기능 구현: 특정 아이피에서 들어온 횟수
        for i in range(0, len(log['events'])-1):
            list_mid = (log['events'][i]['message']).split(" ")
            srcip = str(list_mid[3])
            dstip = str(list_mid[4])
            if srcip not in srciptotal:
                srciptotal[srcip] = 1
            else:
                srciptotal[srcip] += 1

        print ("== 특정 아이피에서 들어온 횟수 ==")
        for key, value in srciptotal.items():
            result = {"timestamp": "%s-%s-%sT%s:%s:%s.%sZ" %(nowtime.year, nowtime.month, nowtime.day, nowtime.hour, nowtime.minute, nowtime.second, str(nowtime.microsecond)[0:2]), "message":(str(key) + ": " + str(value) + "회")} 
            print(result)

        jsonoutput = json.dumps(result)

        if log.get("nextToken"):
            next_token = log["nextToken"]
        else:
            break
    return jsonoutput


def SESSIONcommLogs():
    cnt = 0
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='VPC-flow',
                filterPattern='',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='VPC-flow',
                filterPattern=''
            )
    # 특정 세션간 통신된 횟수
        for i in range(0, len(log['events'])-1):
            list_mid = (log['events'][i]['message']).split(" ")
            srcip = str(list_mid[3])
            dstip = str(list_mid[4])
            if (srcip + " <-> " + dstip) not in srciptotal:
                srciptotal[srcip + " <-> " + dstip] = 1
            else:
                srciptotal[srcip + " <-> " + dstip] += 1
        print ("== 특정 세션간 통신된 횟수 ==")
        for key, value in srciptotal.items():
            result = {"timestamp": "%s-%s-%sT%s:%s:%s.%sZ" %(nowtime.year, nowtime.month, nowtime.day, nowtime.hour, nowtime.minute, nowtime.second, str(nowtime.microsecond)[0:2]), 'message':(str(key) + " : " + str(value), "회")}
            print(result)

        jsonoutput = json.dumps(result)

        if log.get("nextToken"):
            next_token = log["nextToken"]
        else:
            break
    return jsonoutput


def 다른commLogs():
    cnt = 0
    next_token = ''
    while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='VPC-flow',
                filterPattern='',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='VPC-flow',
                filterPattern=''
            )
    # 특정 세션간 통신된 횟수
        for i in range(0, len(log['events'])-1):
            list_mid = (log['events'][i]['message']).split(" ")
            srcip = str(list_mid[3])
            dstip = str(list_mid[4])
            if (srcip + " <-> " + dstip) not in srciptotal:
                srciptotal[srcip + " <-> " + dstip] = 1
            else:
                srciptotal[srcip + " <-> " + dstip] += 1
        print ("== 특정 세션간 통신된 횟수 ==")
        for key, value in srciptotal.items():
            result = {"timestamp": "%s-%s-%sT%s:%s:%s.%sZ" %(nowtime.year, nowtime.month, nowtime.day, nowtime.hour, nowtime.minute, nowtime.second, str(nowtime.microsecond)[0:2]), 'message':(str(key) + " : " + str(value), "회")}
            print(result)

        jsonoutput = json.dumps(result)

        if log.get("nextToken"):
            next_token = log["nextToken"]
        else:
            break
    return jsonoutput
