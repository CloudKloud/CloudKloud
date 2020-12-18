import boto3

AWS_ACCESS_KEY_ID = "AKIA44QAHGX44RFQ2A5O"
AWS_SECRET_ACCESS_KEY = "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"
AWS_DEFAULT_REGION = "ap-northeast-2"

ec2 = boto3.client('ec2',
                aws_access_key_id=AWS_ACCESS_KEY_ID,
                      aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                      region_name=AWS_DEFAULT_REGION)


def mitigate_automate():
   
    #response = ec2.stop_instances(
    #InstanceIds=[
    #    'i-046626673989599b9',
    #]
    #)
    instance_id = "i-0913bd3afa3796883"

    response_total = {
    }

    #response = ec2.describe_vpcs()
    #vpc_id = response.get('Vpcs', [{}])[0].get('VpcId', '')

    try:
        response = ec2.create_security_group(GroupName='IR_TEST_hI',
                                            Description='MITIGATION automate',
                                            )
        security_group_id = response['GroupId']
        print(response)
        response_total[0] = 'Security Group Created %s.' % (security_group_id)

        data = ec2.authorize_security_group_ingress(
            GroupId=security_group_id,
            IpPermissions=[
                {'IpProtocol': 'tcp',
                'FromPort': 22,
                'ToPort': 22,
                'IpRanges': [{'CidrIp': '121.128.223.93/32'}]},
                
        ])
        
        print('Ingress Successfully Set %s' % data)
        response_total[1] = 'Ingress Successfully Set %s' % data

        #data = ec2.revoke_security_group_egress(
        #    GroupId=security_group_id,
        #    IpPermissions=[
                
        #])

        #response_total[2] = 'Egress Successfully Set %s' % data


        response = ec2.modify_instance_attribute(
        
        
        Groups=[
            security_group_id,
        ],
        InstanceId=instance_id,
        
        )
        response_total[2] = 'Security Group %s Successfully set to instance id(%s)' % (security_group_id, instance_id)
        print(response_total)

    except Exception as e:
        print(e)

    return response_total


def instance_list():
    response = ec2.describe_instances()

    return response