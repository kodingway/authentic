from __future__ import unicode_literals
import string

import smtplib

from django.utils.translation import ugettext_lazy as _
from django.utils.encoding import force_text
from django.core.validators import EmailValidator, email_re
from django.core.exceptions import ValidationError

import socket
import dns.resolver
import dns.exception

from . import app_settings

# copied from http://www.djangotips.com/real-email-validation
class EmailValidator(EmailValidator):
    def __init__(self, *args, **kwargs):
        self.rcpt_check = kwargs.pop('rcpt_check', True)
        super(EmailValidator, self).__init__(*args, **kwargs)

    def check_mxs(self, domain):
        try:
            mxs = dns.resolver.query(domain, 'MX')
            mxs = [str(mx.exchange).rstrip('.') for mx in mxs]
            return mxs
        except dns.exception.DNSException:
            try:
                socket.gethostbyname(force_text(domain))
                return [domain]
            except socket.error:
                pass
        return []


    def __call__(self, value):
        super(EmailValidator, self).__call__(value)
        try:
            hostname = value.split('@')[-1]
        except KeyError:
            raise ValidationError(_('Enter a valid email address.'))

        mxs = self.check_mxs(hostname)
        if not mxs:
            raise ValidationError(_('Email domain is invalid'))

        if not self.rcpt_check or not app_settings.A2_VALIDATE_EMAIL:
            return

        try:
            for server in mxs:
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


validate_email = EmailValidator(
    email_re,
    _('Enter a valid email address.'),
    'invalid'
)

def validate_password(password):
    password_set = set(password)
    lower = set(string.lowercase)
    upper = set(string.uppercase)
    punc = set(string.punctuation)

    if not password:
        return
    min_len = app_settings.A2_PASSWORD_POLICY_MIN_LENGTH
    if len(password) < min_len:
        raise ValidationError(_('password must contain at least %d '
            'characters') % min_len)

    class_count = 0
    for cls in (password_set, lower, upper, punc):
        if not password_set.isdisjoint(cls):
            class_count += 1
    min_class_count = app_settings.A2_PASSWORD_POLICY_MIN_CLASSES
    if class_count < min_class_count:
        raise ValidationError(_('password must contain characters '
            'from at least %d classes amon: lowercase letters, '
            'uppercase letters, digits, and punctuations') % min_class_count)
