# List IAM users having 90 days older Access keys

import datetime, boto3, os
from botocore.exceptions import ClientError

# Set the global variables
globalVars  = {}
globalVars['Owner']                 = "Miztiik"
globalVars['Environment']           = "Test"
globalVars['REGION_NAME']           = "ap-south-1"
globalVars['tagName']               = "Valaxy-Serverless-IAM-Key-Sentry"
globalVars['key_age']               = "90"
globalVars['SecOpsArn']             = ""

def get_usr_old_keys( keyAge=90 ):
    client = boto3.client('iam')
    snsClient = boto3.client('sns')
    usersList=client.list_users()
   
    timeLimit=datetime.datetime.now() - datetime.timedelta( days = int(keyAge) )
    usrsWithOldKeys1 = {'Users':[],'Description':'List of users with Key Age greater than (>=) {} days'.format(keyAge),'KeyAgeCutOff':keyAge}

    # Iterate through list of users and compare with `key_age` to flag old key owners
    for k in usersList['Users']:
        accessKeys=client.list_access_keys(UserName=k['UserName'])
    
        for key in accessKeys['AccessKeyMetadata']:
            if key['CreateDate'].date() <= timeLimit.date():
                usrsWithOldKeys['Users'].append({ 'UserName': k['UserName'], 'KeyAgeInDays': (datetime.date.today() - key['CreateDate'].date()).days })

    try:
        snsClient.get_topic_attributes( TopicArn= globalVars['SecOpsArn'] )
        snsClient.publish(TopicArn = globalVars['SecOpsArn'], Message = str(usrsWithOldKeys) )
        usrsWithOldKeys['SecOpsEmailed']="Yes"
    
    except ClientError as e:
        usrsWithOldKeys['SecOpsEmailed']="No - SecOpsArn is Incorrect"

    return usrsWithOldKeys


def lambda_handler(event, context):   
    # Set the default cutoff if env variable is not set
    globalVars['key_age'] = int(os.getenv('key_age_cutoff_in_days',90))
    globalVars['SecOpsArn']=os.getenv('SecOpsTopicArn')

    return get_usr_old_keys( globalVars['key_age'] )
