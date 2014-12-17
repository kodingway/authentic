from django.contrib.auth import forms
from django.utils.translation import gettext_noop
from django.shortcuts import render

from . import views, app_settings, utils

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
        is_post = request.method == 'POST' and self.submit_name in request.POST
        data = request.POST if is_post  else None
        form = forms.AuthenticationForm(data=data)
        is_secure = request.is_secure

        if is_post and form.is_valid():
            if is_secure:
                how = 'password-on-https'
            else:
                how = 'password'
            return utils.login(request, form.get_user(), how)
        return render(request, 'authentic2/login_password_form.html', {
                'submit_name': self.submit_name,
                'form': form
            },
            context_instance=context_instance)

    def profile(self, request, *args, **kwargs):
        return views.login_password_profile(request, *args, **kwargs)
