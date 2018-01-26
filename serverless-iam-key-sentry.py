# List IAM users having 90 days older Access keys

import datetime, boto3, os, json
from botocore.exceptions import ClientError

# Set the global variables
globalVars  = {}
globalVars['Owner']                 = "Miztiik"
globalVars['Environment']           = "Test"
globalVars['REGION_NAME']           = "ap-south-1"
globalVars['tagName']               = "Valaxy-Serverless-IAM-Key-Sentry"
globalVars['key_age']               = "90"
globalVars['SecOpsTopicArn']        = ""

def get_usr_old_keys( keyAge ):
    client = boto3.client('iam',region_name = globalVars['REGION_NAME'])
    snsClient = boto3.client('sns',region_name = globalVars['REGION_NAME'])
    usersList=client.list_users()
   
    timeLimit=datetime.datetime.now() - datetime.timedelta( days = int(keyAge) )
    usrsWithOldKeys = {'Users':[],'Description':'List of users with Key Age greater than (>=) {} days'.format(keyAge),'KeyAgeCutOff':keyAge}

    # Iterate through list of users and compare with `key_age` to flag old key owners
    for k in usersList['Users']:
        accessKeys=client.list_access_keys(UserName=k['UserName'])
    
        # Iterate for all users
        for key in accessKeys['AccessKeyMetadata']:
            if key['CreateDate'].date() <= timeLimit.date():
                usrsWithOldKeys['Users'].append({ 'UserName': k['UserName'], 'KeyAgeInDays': (datetime.date.today() - key['CreateDate'].date()).days })

        # If no users found with older keys, add message in response
        if not usrsWithOldKeys['Users']:
            usrsWithOldKeys['OldKeyCount'] = 'Found 0 Keys that are older than {} days'.format(keyAge)
        else:
            usrsWithOldKeys['OldKeyCount'] = 'Found {0} Keys that are older than {1} days'.format(len(usrsWithOldKeys['Users']), keyAge)

    try:
        snsClient.get_topic_attributes( TopicArn= globalVars['SecOpsTopicArn'] )
        snsClient.publish(TopicArn = globalVars['SecOpsTopicArn'], Message = json.dumps(usrsWithOldKeys, indent=4) )
        usrsWithOldKeys['SecOpsEmailed']="Yes"
    except ClientError as e:
        usrsWithOldKeys['SecOpsEmailed']="No - SecOpsTopicArn is Incorrect"

    return usrsWithOldKeys


def lambda_handler(event, context):   
    # Set the default cutoff if env variable is not set
    globalVars['key_age'] = int(os.getenv('key_age',90))
    globalVars['SecOpsTopicArn']=str(os.getenv('SecOpsTopicArn'))

    return get_usr_old_keys( globalVars['key_age'] )
