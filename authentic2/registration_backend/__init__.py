from django.conf import settings
from django.template.loader import render_to_string

from registration.models import RegistrationProfile

def send_activation_email(self, site):
    """
    Send an activation email to the user associated with this
    ``RegistrationProfile``.
    
    The activation email will make use of two templates:

    ``registration/activation_email_subject.txt``
        This template will be used for the subject line of the
        email. Because it is used as the subject line of an email,
        this template's output **must** be only a single line of
        text; output longer than one line will be forcibly joined
        into only a single line.

    ``registration/activation_email.txt``
        This template will be used for the body of the email.

    These templates will each receive the following context
    variables:

    ``user``
        The new user account

    ``activation_key``
        The activation key for the new account.

    ``expiration_days``
        The number of days remaining during which the account may
        be activated.

    ``site``
        An object representing the site on which the user
        registered; depending on whether ``django.contrib.sites``
        is installed, this may be an instance of either
        ``django.contrib.sites.models.Site`` (if the sites
        application is installed) or
        ``django.contrib.sites.models.RequestSite`` (if
        not). Consult the documentation for the Django sites
        framework for details regarding these objects' interfaces.

    """
    ctx_dict = {'activation_key': self.activation_key,
                'user': self.user,
                'expiration_days': settings.ACCOUNT_ACTIVATION_DAYS,
                'site': site}
    subject = render_to_string('registration/activation_email_subject.txt',
                               ctx_dict)
    # Email subject *must not* contain newlines
    subject = ''.join(subject.splitlines())
    
    message = render_to_string('registration/activation_email.txt',
                               ctx_dict)
    
    self.user.email_user(subject, message, settings.DEFAULT_FROM_EMAIL)
RegistrationProfile.send_activation_email = send_activation_email
