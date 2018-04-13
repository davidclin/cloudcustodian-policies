# cloudcustodian-orphaned-security-groups
Cloud Custodian policy that logs unused security groups

## Resource
https://github.com/capitalone/cloud-custodian/pull/379

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

