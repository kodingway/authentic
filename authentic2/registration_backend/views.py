import logging


from django.shortcuts import redirect, render
from django.utils.translation import ugettext as _
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.sites.models import RequestSite
from django.contrib.sites.models import Site
from django.contrib.auth.models import BaseUserManager
from django.conf import settings


from registration.views import RegistrationView as BaseRegistrationView
from registration.models import RegistrationProfile
from registration import signals

from .. import models, app_settings, compat
from . import urls


logger = logging.getLogger(__name__)


class RegistrationView(BaseRegistrationView):
    form_class = urls.get_form_class(app_settings.A2_REGISTRATION_FORM_CLASS)

    def register(self, request, **cleaned_data):
        User = compat.get_user_model()
        if Site._meta.installed:
            site = Site.objects.get_current()
        else:
            site = RequestSite(request)
        user_fields = {}
        # keep non password fields
        for field in compat.get_registration_fields():
            if not field.startswith('password'):
                user_fields[field] = cleaned_data[field]
            if field == 'email':
                user_fields[field] = BaseUserManager.normalize_email(user_fields[field])
        new_user = User(is_active=False, **user_fields)
        new_user.clean()
        new_user.set_password(cleaned_data['password1'])
        new_user.save()
        attributes = models.Attribute.objects.filter(
                asked_on_registration=True)
        if attributes:
            for attribute in attributes:
                attribute.set_value(new_user, cleaned_data[attribute.name])
        registration_profile = RegistrationProfile.objects.create_profile(new_user)
        registration_profile.send_activation_email(site)

        signals.user_registered.send(sender=self.__class__,
                                     user=new_user,
                                     request=request)
        return new_user

    def registration_allowed(self, request):
        """
        Indicate whether account registration is currently permitted,
        based on the value of the setting ``REGISTRATION_OPEN``. This
        is determined as follows:

        * If ``REGISTRATION_OPEN`` is not specified in settings, or is
          set to ``True``, registration is permitted.

        * If ``REGISTRATION_OPEN`` is both specified and set to
          ``False``, registration is not permitted.
        
        """
        return getattr(settings, 'REGISTRATION_OPEN', True)

    def get_success_url(self, request, user):
        """
        Return the name of the URL to redirect to after successful
        user registration.
        
        """
        return ('registration_complete', (), {})

register = RegistrationView.as_view()


@login_required
def delete(request, next_url='/'):
    next_url = request.build_absolute_uri(request.META.get('HTTP_REFERER') or next_url)
    if not app_settings.A2_REGISTRATION_CAN_DELETE_ACCOUNT:
        return redirect(next_url)
    if request.method == 'POST':
        if 'submit' in request.POST:
            models.DeletedUser.objects.delete_user(request.user)
            logger.info(u'deletion of account %s requested' % request.user)
            messages.info(request, _('Your account has been scheduled for deletion. You cannot use it anymore.'))
            return redirect('auth_logout')
        else:
            return redirect(next_url)
    return render(request, 'registration/delete_account.html')
