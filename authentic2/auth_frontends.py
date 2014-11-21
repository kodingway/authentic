from django.contrib.auth import forms
from django.contrib.auth import REDIRECT_FIELD_NAME, login
from django.utils.translation import gettext_noop
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.conf import settings

from authentic2.constants import NONCE_FIELD_NAME

from . import views, models, app_settings

class LoginPasswordBackend(object):
    submit_name = 'login-password-submit'

    def enabled(self):
        return app_settings.A2_AUTH_PASSWORD_ENABLE

    def name(self):
        return gettext_noop('Password')

    def id(self):
        return 'password'

    def login(self, request, *args, **kwargs):
        context_instance = kwargs.get('context_instance', None)
        next_url = request.GET.get(REDIRECT_FIELD_NAME) or settings.LOGIN_REDIRECT_URL
        nonce = request.GET.get(NONCE_FIELD_NAME,'')
        is_post = request.method == 'POST' and self.submit_name in request.POST
        data = request.POST if is_post  else None
        form = forms.AuthenticationForm(data=data)
        is_secure = request.is_secure

        if is_post and form.is_valid():
            # Login the user
            login(request, form.get_user())
            # Keep a trace
            if is_secure:
                how = 'password-on-https'
            else:
                how = 'password'
            user = form.get_user()
            models.AuthenticationEvent(who=unicode(user)[:80], how=how,
                    nonce=nonce).save()
            return HttpResponseRedirect(next_url)
        return render(request, 'authentic2/login_password_form.html', {
                'submit_name': self.submit_name,
                'form': form
            },
            context_instance=context_instance)

    def profile(self, request, *args, **kwargs):
        return views.login_password_profile(request, *args, **kwargs)
