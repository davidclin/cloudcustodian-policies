The custom iam.py site-package should live in c7n_mailer site-package directory:

/home/ubuntu/c7n_mailer/lib/python2.7/site-packages/c7n/resources/iam.py


The following block of code was modified to support filtering
on specific IAM Policy actions:

<pre>
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
</pre>
