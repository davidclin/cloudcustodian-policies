# Cloud Custodian Examples
1. **security-groups-unused.yml** : Cloud Custodian policy that filters unused security groups based on regex <br>
2. **iam.yml**                    : Cloud Custodian policy that filters iam users based on regex <br>
3. **mfa.yml**                    : Cloud Custodian policy that filters iam users with MFA enabled <br>

## Resource(s)
https://github.com/capitalone/cloud-custodian/pull/379 <br>
https://github.com/capitalone/cloud-custodian/issues/1437

## Schemas 

### security-group

<pre>
(custodian) [hostname]$ custodian schema security-group
aws.security-group:
  actions: [auto-tag-user, delete, invoke-lambda, mark, mark-for-op, normalize-tag,
    notify, patch, put-metric, remove-permissions, remove-tag, rename-tag, tag, tag-trim,
    unmark, untag]
  filters: [and, default-vpc, diff, egress, event, ingress, json-diff, locked, marked-for-op,
    not, or, stale, tag-count, unused, used, value]
</pre>

### iam-user

<pre>
(custodian) [hostname]$ custodian schema iam-user
aws.iam-user:
  actions: [delete, invoke-lambda, notify, put-metric, remove-keys]
  filters: [access-key, and, credential, event, group, mfa-device, not, or, policy,
    value]
</pre>

## Artifacts

### security-groups-unused.yml
<pre>
(custodian) [hostname]$ custodian run --dryrun -s . security-groups-unused.yml
2018-04-13 20:02:01,043: custodian.policy:INFO policy: security-groups-unused resource:security-group region:us-east-1 count:29 time:0.30

(custodian) [hostname]$ more ./security-groups-unused/resources.json | grep 'GroupName\|GroupId'
(custodian) [ec2-user@ip-10-100-0-195 custodian]$ more ./security-groups-unused/resources.json | grep GroupName\"\:
    "GroupName": "rds-launch-wizard-5",
    "GroupName": "rds-launch-wizard",
    "GroupName": "rds-launch-wizard-2",
    "GroupName": "launch-wizard-17",
    "GroupName": "launch-wizard-5",
    "GroupName": "launch-wizard-7",
    "GroupName": "launch-wizard-6",
    "GroupName": "launch-wizard-1",
    "GroupName": "rds-launch-wizard-4",
    "GroupName": "launch-wizard-4",
    "GroupName": "launch-wizard-2",
    "GroupName": "launch-wizard-3",
    etc.
</pre>

### iam.yml
<pre>
(custodian) [ec2-user@ip-10-100-0-195 custodian]$ custodian run --dryrun -s . iam.yml
2018-04-13 22:51:05,472: custodian.policy:INFO policy: iam-user-filter-policy resource:iam-user region:us-east-1 count:1 time:0.01

(custodian) [hostname]$ more ./iam-user-filter-policy/resources.json | grep UserName\"\:
    "UserName": "david.lin",
</pre>

### mfa.yml
<pre>
(custodian) [hostname]$ custodian run --dryrun mfa.yml -s .
2018-04-13 23:47:40,901: custodian.policy:INFO policy: mfa-user-filter-policy resource:iam-user region:us-east-1 count:15 time:0.01

(custodian) [ec2-user@ip-10-100-0-195 cloudcustodian]$ more ./mfa-user-filter-policy/resources.json | grep UserName\"\:
    "UserName": "brandon.winningham",
    "UserName": "david.lin.ctr",
    "UserName": "eric.schanberger",
    "UserName": "jesse.lavigne",
    "UserName": "jmarcoux",
    "UserName": "jonathan.voigt",
    "UserName": "kosta.djukic.ctr",
    "UserName": "mike.garrison",
    "UserName": "ngallaher",
    "UserName": "nikos.michalakis",
    "UserName": "omar.akkawi",
    "UserName": "peter.richmond",
    "UserName": "ramya.ravula.ctr",
    "UserName": "simon.stent",
    "UserName": "srikanth.yadav.ctr",
</pre>
