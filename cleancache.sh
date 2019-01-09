#!/bin/bash

# to find path of cache issue `sudo find / cloud-custodian.cache

# for ubuntu
rm ~/.cache/cloud-custodian.cache

# for centos
# rm /home/ec2-user/.cache/cloud-custodian.cache

echo 'Cloud Custodian cache deleted'
