#! /usr/bin/env bash

# Create a rule to enable CloudWatch events for all Amazon GuardDuty findings
aws events put-rule --name AmazonGuardDutyFindings --event-pattern '{"source":["aws.guardduty"]}'

# Connect our AWS Lambda function to all findings
aws events put-targets --rule RespondToAmazonGuardDutyViaDeepSecurity --targets Id=1,Arn=arn:aws:lambda:us-east-1:111122223333:function:RespondToAmazonGuardDutyViaDeepSecurity

# Set the invocation rights for the AWS Lambda function
aws lambda add-permission --function-name RespondToAmazonGuardDutyViaDeepSecurity --statement-id 1 --action 'lambda:InvokeFunction' --principal events.amazonaws.com