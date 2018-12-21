#!/bin/bash
PATH=/home/ubuntu/bin:/home/ubuntu/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
export PATH
source c7n_mailer/bin/activate
echo "Running MFA audit policies..."
custodian run -c /home/ubuntu/cloudcustodian/policies/mfa-audit.yml -s output --region us-east-1
echo "MFA audit policies completed"


