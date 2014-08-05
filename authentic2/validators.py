from __future__ import unicode_literals

import smtplib

from django.utils.translation import ugettext_lazy as _
from django.core.validators import EmailValidator
from django.core.exceptions import ValidationError

import dns.resolver

# copied from http://www.djangotips.com/real-email-validation
class EmailValidator(EmailValidator):

    def __call__(self, value):
        super(EmailValidator, self).__call__(value)
        try:
            hostname = value.split('@')[-1]
        except KeyError:
            raise ValidationError(_('Enter a valid email address.'))

        try:
            for server in [ str(r.exchange).rstrip('.') \
                            for r \
                            in dns.resolver.query(hostname, 'MX') ]:
                try:
                    smtp = smtplib.SMTP()
                    smtp.connect(server)
                    status = smtp.helo()
                    if status[0] != 250:
                        continue
                    smtp.mail('')
                    status = smtp.rcpt(value)
                    if status[0] % 100 == 5:
                        raise ValidationError(_('Invalid email address.'))
                    break
                except smtplib.SMTPServerDisconnected:
                    break
                except smtplib.SMTPConnectError:
                    continue
        except dns.resolver.NXDOMAIN:
            raise ValidationError(_('Nonexistent domain.'))
        except dns.resolver.NoAnswer:
            raise ValidationError(_('Nonexistent email address.'))

try:
    from django.core.exceptions import email_re
except ImportError:
    # post Django 1.6
    validate_email = EmailValidator()
else:
    # pre Django 1.6
    validate_email = EmailValidator(
        email_re,
        _('Enter a valid email address.'),
        'invalid'
    )
