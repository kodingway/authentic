import logging
from datetime import datetime

from django.conf import settings
from django.shortcuts import redirect, render
from django.utils.translation import ugettext as _
from django.contrib import messages
from django.contrib.auth import authenticate, login as django_login, logout
from django.db.models import FieldDoesNotExist
from django.db import IntegrityError
from django.template.loader import render_to_string
from django.core import signing
from django.views.generic.edit import FormView
from django.views.generic.base import TemplateView, View

from authentic2.utils import get_form_class
from .. import models, app_settings, compat

logger = logging.getLogger(__name__)

User = compat.get_user_model()

def valid_token(method):
    def f(obj, *args, **kwargs):
        try:
            registration_kwargs = signing.loads(kwargs['registration_token'],
                                                max_age=settings.ACCOUNT_ACTIVATION_DAYS*3600*24)
            params = kwargs.copy()
            params.update(registration_kwargs)
        except signing.SignatureExpired:
            return redirect('registration_activation_expired')
        except signing.BadSignature:
            return redirect('registration_activation_failed')
        return method(obj, *args, **params)
    return f

def login(request, user, redirect_url='auth_homepage'):
    user.backend = 'authentic2.backends.ModelBackend'
    django_login(request, user)
    return redirect(redirect_url)

class RegistrationView(FormView):
    form_class = get_form_class(app_settings.A2_REGISTRATION_FORM_CLASS)
    template_name = 'registration/registration_form.html'

    def form_valid(self, form):
        form.save(self.request)
        return redirect('registration_complete')

class RegistrationCompletionView(FormView):
    form_class = get_form_class(app_settings.A2_REGISTRATION_COMPLETION_FORM_CLASS)
    http_method_names = ['get', 'post']
    template_name = 'registration/registration_completion_form.html'

    @valid_token
    def get(self, request, *args, **kwargs):
        if app_settings.A2_REGISTRATION_EMAIL_IS_UNIQUE:
            try:
                user = User.objects.get(email__iexact=kwargs['email'])
            except User.DoesNotExist:
                return super(RegistrationCompletionView, self).get(request, *args, **kwargs)
            return login(request, user)
        else:
            if 'create' in request.GET:
                return super(RegistrationCompletionView, self).get(request, *args, **kwargs)
            if 'username' in request.GET:
                try:
                    user = User.objects.get(email__iexact=kwargs['email'],
                                            username=request.GET['username'])
                    return login(request, user)
                except User.DoesNotExist:
                    pass

            user_accounts = User.objects.filter(email__iexact=kwargs['email'])
            if user_accounts:
                logout(request)
                context = kwargs.copy()
                context.update({'accounts': user_accounts})
                self.template_name = 'registration/login_choices.html'
                return self.render_to_response(context)
            else:
                return super(RegistrationCompletionView, self).get(request, *args, **kwargs)

    @valid_token
    def post(self, request, *args, **kwargs):
        form = self.get_form(self.form_class)
        if form.is_valid():
            params = form.cleaned_data.copy()
            params.update(kwargs)
            user, next_url = form.save(**params)
            if next_url:
                return login(request, user, next_url)
            return login(request, user)
        else:
            return self.form_invalid(form)

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
