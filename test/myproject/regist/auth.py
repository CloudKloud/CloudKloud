import boto3



def auth(accesskeyid, secretaccesskey):
    
    try:
        
        logs = boto3.client('logs', aws_access_key_id=accesskeyid, aws_secret_access_key=secretaccesskey, region_name = "ap-northeast-2")
        result = logs.describe_log_groups()
        
        return True
    except Exception as ex:
        print(ex)
        pass
    return False
