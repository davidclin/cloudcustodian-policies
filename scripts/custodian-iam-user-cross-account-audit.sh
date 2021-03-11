#!/bin/bash

# ===========
# DESCRIPTION
# ===========
# This script is used as part of an company's offboarding process to
# retrieve a list of IAM users across all AWS accounts under the AWS org.
#
# This script uses c7n-org's orgaccounts.py script to generate a yml file named
# offboading-orgaccounts.yml which contains the list of all known AWS accounts
# under the AWS org.
#
# The offboarding-orgaccounts.yml file is then used by c7n-org to
# search against all IAM users and write the results to file.
#
# VIM is used to open the file to quickly search for IAM user(s) being offboarded.
#
# Within vim, you can use the `/` command to search against usernames.
# If a match is found, the account name that maps to the aws account number
# can be found in the offboarding-oraccounts.yml file.

# =========
# VARIABLES
# =========
# ORGACCOUNTSPATH is the path where c7n-org's orgaccounts.py lives
# ORGACCOUNTSFILE is the name of the file generated after orgaccounts.py is invoked
# C7NORGPATH      is the path where the output file offboarding-iam-users-audit.yml is stored

ORGACCOUNTSPATH="/home/ubuntu/cloud-custodian/tools/c7n_org/scripts"
ORGACCOUNTSFILE="offboarding-orgaccounts.yml"
C7NORGPATH="/home/ubuntu/cloudcustodian/policies/c7n-org"


echo "Creating $ORGACCOUNTSFILE file. This will take a minute..."
python $ORGACCOUNTSPATH/orgaccounts.py -f $ORGACCOUNTSPATH/$ORGACCOUNTSFILE
echo "offboarding-orgaccounts.yml file successfully created!"

echo "Retrieving list of all IAM users across org..."
echo "You will be taken into a VIM session upon completion"
echo "Use the forward slash '/' to search file against IAM user(s)"
source "/home/ubuntu/c7n_org/bin/activate"
c7n-org run -s output -c $ORGACCOUNTSPATH/$ORGACCOUNTSFILE -u $C7NORGPATH/offboarding-iam-users-audit.yml
c7n-org report -c  $ORGACCOUNTSPATH/$ORGACCOUNTSFILE -u $C7NORGPATH/offboarding-iam-users-audit.yml -s output --region us-east-1 > /home/ubuntu/cloudcustodian/policies/c7n-org/offboar
ding-iam-users-audit.txt
vim $C7NORGPATH/iam-users-in-cross-accounts.txt
echo "IAM user audit across accounts completed"
echo "If you would like to see the results again, see file $C7NORGPATH/offboarding-iam-users-audit.txt"
