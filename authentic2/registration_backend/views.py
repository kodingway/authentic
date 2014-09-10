import logging
from datetime import datetime

from django.shortcuts import redirect, render
from django.utils.translation import ugettext as _
from django.contrib import messages
from django.contrib.sites.models import Site, RequestSite
from django.contrib.auth.models import BaseUserManager, Group
from django.conf import settings
from django.db.models import FieldDoesNotExist
from django.db import IntegrityError
from django.core import signing
from django.core.mail import send_mail

from django.template.loader import render_to_string

from django.views.generic.edit import FormView
from django.views.generic.base import TemplateView

from authentic2.utils import get_form_class
from .. import models, app_settings, compat

EXPIRATION = settings.ACCOUNT_ACTIVATION_DAYS

logger = logging.getLogger(__name__)

class RegistrationView(FormView):
    form_class = get_form_class(app_settings.A2_REGISTRATION_FORM_CLASS)
    template_name = 'registration/registration_form.html'

    def form_valid(self, form):
        if Site._meta.installed:
            site = Site.objects.get_current()
        else:
            site = RequestSite(self.request)

        activation_key = signing.dumps(form.cleaned_data)
        ctx_dict = {'activation_key': activation_key,
                    'user': form.cleaned_data,
                    'expiration_days': EXPIRATION,
                    'site': site}

        subject = render_to_string('registration/activation_email_subject.txt',
                                   ctx_dict)

        subject = ''.join(subject.splitlines())
        message = render_to_string('registration/activation_email.txt',
                                   ctx_dict)

        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL,
                  [form.cleaned_data['email']], fail_silently=True)
        return redirect('registration_complete')

register = RegistrationView.as_view()

class ActivationView(TemplateView):
    http_method_names = ['get']
    template_name = 'registration/activate.html'

    def get(self, request, *args, **kwargs):
        context = {}
        try:
            self.register(kwargs['activation_key'])
            return redirect('registration_activation_complete')
        except signing.SignatureExpired:
            context['expired'] = True
        except IntegrityError:
            context['existing_user'] = True
        return self.render_to_response(context)

    def register(self, registration_token):
        User = compat.get_user_model()
        registration_fields = signing.loads(registration_token,
                                            max_age=EXPIRATION * 3600 * 24)
        user_fields = {}
        for field in compat.get_registration_fields():
            # save User model fields
            try:
                User._meta.get_field(field)
            except FieldDoesNotExist:
                continue
            if field.startswith('password'):
                continue
            user_fields[field] = registration_fields[field]
            if field == 'email':
                user_fields[field] = BaseUserManager.normalize_email(user_fields[field])

        new_user = User(is_active=True, **user_fields)
        new_user.clean()
        new_user.set_password(registration_fields['password1'])
        new_user.save()

        attributes = models.Attribute.objects.filter(
                asked_on_registration=True)
        if attributes:
            for attribute in attributes:
                attribute.set_value(new_user, registration_fields[attribute.name])
        if app_settings.A2_REGISTRATION_GROUPS:
            groups = []
            for name in app_settings.A2_REGISTRATION_GROUPS:
                group, created = Group.objects.get_or_create(name=name)
                groups.append(group)
            new_user.groups = groups
        return new_user

class DeleteView(TemplateView):
    def get(self, request, *args, **kwargs):
        next_url = request.build_absolute_uri(request.META.get('HTTP_REFERER')\
                                              or request.GET.get('next_url'))
        if not app_settings.A2_REGISTRATION_CAN_DELETE_ACCOUNT:
            return redirect(next_url)
        return render(request, 'registration/delete_account.html')

    def post(self, request, *args, **kwargs):
        next_url = request.build_absolute_uri(request.META.get('HTTP_REFERER')\
                                              or request.GET.get('next_url'))
        if 'submit' in request.POST:
            models.DeletedUser.objects.delete_user(request.user)
            logger.info(u'deletion of account %s requested' % request.user)
            messages.info(request, _('Your account has been scheduled for deletion. You cannot use it anymore.'))
            return redirect('auth_logout')
        else:
            return redirect(next_url)
