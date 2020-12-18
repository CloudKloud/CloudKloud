import boto3

AWS_ACCESS_KEY_ID = "KEY_VALUE"
AWS_SECRET_ACCESS_KEY = "SECRET_KEY_VALUE"
AWS_DEFAULT_REGION = "ap-northeast-2"

logs = boto3.client('logs',
                  aws_access_key_id=AWS_ACCESS_KEY_ID,
                      aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                      region_name=AWS_DEFAULT_REGION)

cnt = 0
next_token = ''
while True:
        if next_token:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
                nextToken=next_token
            )
        else:
            log = logs.filter_log_events(
                logGroupName='all_region_cloudtrail',
            )
        for i in log['events']:
            cnt += 1
            result = {"timestamp": i.get("timestamp"), "message": i.get('message')}
            print(result)
            print(cnt)

        if log.get("nextToken"):
            next_token = log["nextToken"]
        else:
            break