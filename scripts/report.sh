#!/bin/bash
#
# This script invokes the Cloud Custodian iam-user-tagged-resources-audit.yml
# policy then generates a consolidated report of AWS resources 
# that match the given IAM user specified by the Owner tag.
#
# To change the owner, find/replace the IAM user in
# iam-user-tagged-resource.audit.yml. 
#
# By default, the policy is invoked in us-east-1.
# The region can be modified by changing the value of variable 'REGION'.
#
# Upon completion, the consolidated report can be found here: 
# /home/ubuntu/cloudcustodian/policies/report.txt
#

# Variables
RESOURCE=ebs,ebs-snapshot,security-group,s3,ami,dynamodb-table,dynamodb-stream,dynamodb-backup,elasticsearch,elb,eni,lambda,lambda-layer,rds,s3,sqs,sns,cfn
REGION="--region us-east-1"
CUSTODIAN_POLICY="/home/ubuntu/cloudcustodian/policies/iam-user-tagged-resources-audit.yml"
CUSTODIAN_OUTPUT_DIRECTORY="/home/ubuntu/cloudcustodian/policies/output"
CUSTODIAN_REPORT="/home/ubuntu/cloudcustodian/policies/report.txt"

# Activate c7n virtual environment
cd /home/ubuntu
source c7n_mailer/bin/activate

# Clear c7n cache
echo '------------------'
echo 'Clearing c7n cache '
echo '------------------'
rm /home/ubuntu/.cache/cloud-custodian.cache
echo '~/.cachecloud-custodian.cache cleared'

# Invoke c7n policy
echo '-------------------'
echo 'Invoking c7n policy'
echo '-------------------'
custodian run -s $CUSTODIAN_OUTPUT_DIRECTORY $CUSTODIAN_POLICY $REGION

# Generate c7n reports
echo '-------------------------------'
echo 'Generating report for resources'
echo '-------------------------------'

# Write ec2 report to file
echo 'ec2'
echo 'ec2' > $CUSTODIAN_REPORT
custodian report -s $CUSTODIAN_OUTPUT_DIRECTORY -t ec2 $CUSTODIAN_POLICY --field tag:Owner=tag:Owner --format grid >> $CUSTODIAN_REPORT
echo ' ' >> $CUSTODIAN_REPORT

# Append more resources to file
for i in $(echo $RESOURCE | sed "s/,/ /g")
do
    # Loop through the RESOURCE list 
    echo $i  
    echo $i >> $CUSTODIAN_REPORT
    custodian report -s $CUSTODIAN_OUTPUT_DIRECTORY -t $i $CUSTODIAN_POLICY --field tag:Owner=tag:Owner --format grid >> $CUSTODIAN_REPORT
    echo ' ' >> $CUSTODIAN_REPORT
done

echo ''
echo '-------------------------------'
echo 'Report'
echo '-------------------------------'
more $CUSTODIAN_REPORT

echo ''
echo 'Report completed!                                  '
echo 'See /home/ubuntu/cloudcustodian/policies/report.txt'
