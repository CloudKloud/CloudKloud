from django.shortcuts import render
import boto3
import json
# Create your views here.
from django.template.loader import render_to_string
from multiprocessing import Process
from regist.models import accessKeyIDPW
import time

db = accessKeyIDPW.objects.all()
if db:
    AWS_ACCESS_KEY_ID = db[0].accesskeyid
    AWS_SECRET_ACCESS_KEY = db[0].secretaccesskey
    AWS_DEFAULT_REGION = db[0].awsconfigregion
    logs = boto3.client('logs',
                        aws_access_key_id=AWS_ACCESS_KEY_ID,
                        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                        region_name=AWS_DEFAULT_REGION)
    ec2 = boto3.client('ec2', aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                       region_name=AWS_DEFAULT_REGION)
res = []

def auth_check():
    db = accessKeyIDPW.objects.all()
    if not db:
        return "incomplete"
    else:
        return "complete"

def maps(request):
    return render(request, 'map/MainPage.html')


def regionjson(request):
    
    db = accessKeyIDPW.objects.all()
    if db:
        
   
    

        def MaliciousIP(): # Malicious IP 로그 전체 추출
            cnt = 0
            output = []
            next_token = ''

            # 파일 내용 리스트로 받아오기
            # 파일 다운로드 : https://rescure.me/rescure_blacklist.txt
            ## 파일 위치 변경 필요
            list_file = open('C:\\malicious.txt', 'r').read().split('\n')
            #print(list_file)

            while True:

                log = logs.filter_log_events(
                    logGroupName='all_region_cloudtrail'
                )
                for i in log['events']:
                    msg_json = json.loads(i.get('message'))
                    # 리스트와 ip 값(msg_json['sourceIPAddress'])이 같은지 비교하기
                    try:
                        for ip in list_file:
                            if msg_json['sourceIPAddress'] in ip:
                                cnt += 1
                                #print(msg_json['sourceIPAddress'])
                                result = msg_json['awsRegion']
                                output.append(result)
                                #print(result)
                                #print(cnt)
                    except:
                        continue

                #jsonoutput = json.dumps(output)



                return output



        jsons=MaliciousIP()
        new_list = []
        for v in jsons:
            if v not in new_list:
                new_list.append(v)

        context = {
            'object': new_list, 'auth' : auth_check()
            #'output': res
        }
        



        return render(request, 'map/MainPage2.html', context)
    else:
        return render(request, 'regist/regist.html')



