# Cloud Custodian Examples
1. Cloud Custodian policy that logs unused security groups based on regex <br>
2. Cloud Custodian policy that logs iam users based on regex

## Resource(s)
https://github.com/capitalone/cloud-custodian/pull/379 <br>
https://github.com/capitalone/cloud-custodian/issues/1437

## security-group schema

<pre>
(custodian) [hostname]$ custodian schema security-group
aws.security-group:
  actions: [auto-tag-user, delete, invoke-lambda, mark, mark-for-op, normalize-tag,
    notify, patch, put-metric, remove-permissions, remove-tag, rename-tag, tag, tag-trim,
    unmark, untag]
  filters: [and, default-vpc, diff, egress, event, ingress, json-diff, locked, marked-for-op,
    not, or, stale, tag-count, unused, used, value]
</pre>

## Unused Security Group Artifact

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

## iam schema

<pre>

</pre>
