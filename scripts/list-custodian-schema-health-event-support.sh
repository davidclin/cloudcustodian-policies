#!/bin/bash
#
# Find aws resources that support the "health-event" filter with "issue" category
#

# List of services from 'custodian schema'
SERVICE=account,acm-certificate,alarm,ami,app-elb,app-elb-target-group,asg,backup-plan,batch-compute,batch-definition,cache-cluster,cache-snapsho
t,cache-subnet-group,cfn,cloud-directory,cloudhsm-cluster,cloudsearch,cloudtrail,codebuild,codecommit,codepipeline,config-recorder,config-rule,cu
stomer-gateway,datapipeline,dax,directconnect,directory,distribution,dlm-policy,dms-endpoint,dms-instance,dynamodb-backup,dynamodb-stream,dynamod
b-table,ebs,ebs-snapshot,ec2,ec2-reserved,ecr,ecs,ecs-container-instance,ecs-service,ecs-task,ecs-task-definition,efs,efs-mount-target,eks,elasti
cbeanstalk,elasticbeanstalk-environment,elasticsearch,elb,emr,eni,event-rule,event-rule-target,firehose,fsx,fsx-backup,gamelift-build,gamelift-fl
eet,glacier,glue-connection,glue-crawler,glue-database,glue-dev-endpoint,glue-job,glue-table,health-event,healthcheck,hostedzone,hsm,hsm-client,h
sm-hapg,iam-certificate,iam-group,iam-policy,iam-profile,iam-role,iam-user,identity-pool,internet-gateway,iot,kafka,key-pair,kinesis,kinesis-anal
ytics,kms,kms-key,lambda,lambda-layer,launch-config,launch-template-version,lightsail-db,lightsail-elb,lightsail-instance,log-group,message-broke
r,ml-model,nat-gateway,network-acl,network-addr,ops-item,opswork-cm,opswork-stack,peering-connection,r53domain,rds,rds-cluster,rds-cluster-param-
group,rds-cluster-snapshot,rds-param-group,rds-reserved,rds-snapshot,rds-subnet-group,rds-subscription,redshift,redshift-snapshot,redshift-subnet
-group,rest-account,rest-api,rest-resource,rest-stage,rest-vpclink,route-table,rrset,s3,sagemaker-endpoint,sagemaker-endpoint-config,sagemaker-jo
b,sagemaker-model,sagemaker-notebook,sagemaker-transform-job,secrets-manager,security-group,shield-attack,shield-protection,simpledb,snowball,sno
wball-cluster,sns,sqs,ssm-activation,ssm-managed-instance,ssm-parameter,step-machine,storage-gateway,streaming-distribution,subnet,support-case,t
ransit-attachment,transit-gateway,user-pool,vpc,vpc-endpoint,vpn-connection,vpn-gateway,waf,waf-regional,workspaces

# Delete old result file
rm result

# Iterate custodian schema
echo '-----------------------------------------------------------------' >> result
echo 'custodian schema service_name.filters.health-event | grep issue' >> result
echo '-----------------------------------------------------------------' >> result


for i in $(echo $SERVICE | sed "s/,/ /g")
do
    # Loop through the SERVICE list
    echo $i >> result
    custodian schema $i.filters.health-event | grep issue >> result
    echo '-----------------------------------------------------------------' >> result
done
