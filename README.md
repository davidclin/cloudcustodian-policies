# cloudcustodian-orphaned-security-groups
Cloud Custodian policy that logs unused security groups

## Resource
https://github.com/capitalone/cloud-custodian/pull/379

## security-group schema

<pre>
(custodian) [ec2-user@ip-10-100-0-195 custodian]$ custodian schema security-group
aws.security-group:
  actions: [auto-tag-user, delete, invoke-lambda, mark, mark-for-op, normalize-tag,
    notify, patch, put-metric, remove-permissions, remove-tag, rename-tag, tag, tag-trim,
    unmark, untag]
  filters: [and, default-vpc, diff, egress, event, ingress, json-diff, locked, marked-for-op,
    not, or, stale, tag-count, unused, used, value]
</pre>

## Artifact

<pre>
(custodian) [hostname]$ custodian run --dryrun -s . security-groups-unused.yml
2018-04-13 20:02:01,043: custodian.policy:INFO policy: security-groups-unused resource:security-group region:us-east-1 count:29 time:0.30

(custodian) [hostname]$ more ./security-groups-unused/resources.json | grep 'GroupName\|GroupId'
    "GroupName": "security-group-name-1",
    "GroupId": "sg-aaaaaaaa"
    "GroupName": "security-group-name-2",
    "GroupId": "sg-bbbbbbbb"
    "GroupName": "security-group-name-3",
    "GroupId": "sg-cccccccc"
    etc.    
</pre>

