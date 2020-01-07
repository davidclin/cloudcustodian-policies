# This section of code should be used to replace the has-allow-all function
# in the /cloud-custodian/c7n/resources/iam.py file

    schema = type_schema('has-allow-all')
    permissions = ('iam:ListPolicies', 'iam:ListPolicyVersions')

    def has_allow_all_policy(self, client, resource):
        statements = client.get_policy_version(
            PolicyArn=resource['Arn'],
            VersionId=resource['DefaultVersionId']
        )['PolicyVersion']['Document']['Statement']
        if isinstance(statements, dict):
            statements = [statements]

        for s in statements:
            if ('Condition' not in s and
                    'Action' in s and
                    ('account:*' in s['Action'] or
                    'account:EnableRegion' in s['Action']) and
                    'Resource' in s and
                    isinstance(s['Resource'], six.string_types) and
                    s['Resource'] == "*" and
                    s['Effect'] == "Allow"):
                return True
        return False
