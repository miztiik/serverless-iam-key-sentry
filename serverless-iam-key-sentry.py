# List IAM users having 90 days older Access keys

import datetime, boto3, os

# Set the global variables
globalVars  = {}
globalVars['Owner']                 = "Miztiik"
globalVars['Environment']           = "Test"
globalVars['REGION_NAME']           = "ap-south-1"
globalVars['tagName']               = "Valaxy-Serverless-IAM-Key-Sentry"


def get_usr_old_keys( keyAge ):
    client = boto3.client('iam')
    usersList=client.list_users()
   
    timeLimit=datetime.datetime.now() - datetime.timedelta( days = int(keyAge) )
    usrsWithOldKeys = {'Users':[], 'KeyAgeCutOff':keyAge}

    for k in usersList['Users']:
        accessKeys=client.list_access_keys(UserName=k['UserName'])
    
        for key in accessKeys['AccessKeyMetadata']:
            if key['CreateDate'].date() <= timeLimit.date():
                usrsWithOldKeys['Users'].append({ 'UserName': k['UserName'], 'KeyAgeInDays': (datetime.date.today() - key['CreateDate'].date()).days })

    return usrsWithOldKeys


def lambda_handler(event, context):   
    # Set the default cutoff if env variable is not set
    globalVars['key_age'] = os.getenv('key_age_cutoff_in_days',90)
    return get_usr_old_keys( globalVars['key_age'] )