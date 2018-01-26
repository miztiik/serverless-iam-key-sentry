# Serverless IAM Old Key Sentry
Changing access keys (which consist of an access key ID and a secret access key) on a regular schedule is a well-known security best practice because it shortens the period an access key is active and therefore reduces the business impact if they are compromised. Having an established process that is run regularly also ensures the operational steps around key rotation are verified, so changing a key is never a scary step.

Identifying applications and services with old keys become imperative in those case. We are going to use `Lambda Functions` to periodically check our account for old keys and notify our Security Operations Team using `SNS`

![Fig : Valaxy-Serverless-Security-Group-Sentry](https://raw.githubusercontent.com/miztiik/serverless-sg-sentry/master/images/AWS-IAM-Old-Keys.png)
You can also follow this article in Youtube

## Pre-Requisities
We will need the following pre-requisites to successfully complete this activity,
- Few `IAM Users` with one or two _Access Key_ created in the AWS Region where the solution is deployed
- Security Operations SNS Topic ARN - [If you need assistance, follow this article](https://www.youtube.com/watch?v=7Ic1SQbjpOs)
- IAM Role - _i.e_ `Lambda Service Role` - _with_ `EC2FullAccess` _permissions_
  - _You may use an `Inline` policy with more restrictive permissions_

_The image above shows the execution order, that should not be confused with the numbering of steps given here_


## Step 1 - Configure Lambda Function- `SG-Sentry-Bot`
The below script is written in `Python 2.7`. Remember to choose the same in AWS Lambda Functions.
### Customisations
- `globalVars['key_age']` - Set the `key_age` to any value you desire, by default it is set to 90 days
- `globalVars['SecOpsArn']` - Update the ARN of your SNS Topic

_Change the global variables at the top of the script to suit your needs._
```py
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

```
After pasting the code, Scroll down to create a environment variable Key,
1. Key as `key_age_cutoff_in_days` and Value as `90`
1. Key `SecOpsArn` and Value as `YOUR-SNS-TOPIC-ARN`

`Save` the lambda function

## Step 2 - Configure Lambda Triggers
We are going to use Cloudwatch Scheduled Events to take backup everyday.
```
rate(1 minute)
or
rate(5 minutes)
or
rate(1 day)
# The below example creates a rule that is triggered every day at 12:00pm UTC.
cron(0 12 * * ? *)
```
_If you want to learn more about the above Scheduled expressions,_ Ref: [CloudWatch - Schedule Expressions for Rules](http://docs.aws.amazon.com/AmazonCloudWatch/latest/events/ScheduledEvents.html#RateExpressions)

## Step 3 - Testing the solution
Navigate to the `EC2 console` and choose `Security Groups` and Choose the security group that we are monitoring.
Add a new `Inbound` rule, for example `SSH` on port `22` from `0.0.0.0/0`.

Adding this rule creates an **EC2** `AuthorizeSecurityGroupIngress` service event, which triggers the Lambda function.

After a few moments, choose the refresh button ( The "**refresh**" icon ) to see that the new _ingress_ rule that you just created has been removed by the solution.


### Rotate access keys
After you have identified old keys, You should follow these steps to rotate the keys
1. Create a second access key in addition to the one in use.
1. Update all your applications to use the new access key and validate that the applications are working.
1. Change the state of the previous access key to inactive.
1. Validate that your applications are still working as expected.
1. Delete the inactive access key.

### Summary
We have demonstrated how you can automatically identify users with old Access/Secret Keys.

