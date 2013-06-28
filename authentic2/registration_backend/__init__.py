from django.utils.importlib import import_module
from django.contrib.sites.models import Site, RequestSite


from registration.backends.default import DefaultBackend
from registration.models import RegistrationProfile
from registration import signals


from .. import app_settings
from ..compat import get_user_model


class RegistrationBackend(DefaultBackend):
    def get_form_class(self, request):
        form_class = app_settings.A2_REGISTRATION_FORM_CLASS
        module, form_class = form_class.rsplit('.', 1)
        module = import_module(module)
        return getattr(module, form_class)

    def register(self, request, **kwargs):
        """
        Given a username, email address and password, register a new
        user account, which will initially be inactive.

        Along with the new ``User`` object, a new
        ``registration.models.RegistrationProfile`` will be created,
        tied to that ``User``, containing the activation key which
        will be used for this account.

        An email will be sent to the supplied email address; this
        email should contain an activation link. The email will be
        rendered using two templates. See the documentation for
        ``RegistrationProfile.send_activation_email()`` for
        information about these templates and the contexts provided to
        them.

        After the ``User`` and ``RegistrationProfile`` are created and
        the activation email is sent, the signal
        ``registration.signals.user_registered`` will be sent, with
        the new ``User`` as the keyword argument ``user`` and the
        class of this backend as the sender.

        """
        user_model = get_user_model()
        form_kwargs = {'password': kwargs['password1'],}
        for field in user_model._meta.get_all_field_names():
            if field in kwargs:
                form_kwargs[field] = kwargs[field]

        if Site._meta.installed:
            site = Site.objects.get_current()
        else:
            site = RequestSite(request)
        new_user = RegistrationProfile.objects.create_inactive_user(form_kwargs, site)
        signals.user_registered.send(sender=self.__class__,
            user=new_user,
            request=request)
        return new_user
