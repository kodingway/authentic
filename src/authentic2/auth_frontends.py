from django.contrib.auth import forms
from django.utils.translation import gettext_noop
from django.shortcuts import render
from django.utils.translation import ugettext as _

from . import views, app_settings, utils
from .exponential_retry_timeout import ExponentialRetryTimeout

class LoginPasswordBackend(object):
    submit_name = 'login-password-submit'

    def enabled(self):
        return app_settings.A2_AUTH_PASSWORD_ENABLE

    def name(self):
        return gettext_noop('Password')

    def id(self):
        return 'password'

    def login(self, request, *args, **kwargs):
        exponential_backoff = ExponentialRetryTimeout(key_prefix='login-exp-retry-timeout-',
                duration=app_settings.A2_LOGIN_EXPONENTIAL_RETRY_TIMEOUT_DURATION,
                factor=app_settings.A2_LOGIN_EXPONENTIAL_RETRY_TIMEOUT_FACTOR,
                max_duration=app_settings.A2_LOGIN_EXPONENTIAL_RETRY_TIMEOUT_MAX_DURATION)
        context_instance = kwargs.get('context_instance', None)
        is_post = request.method == 'POST' and self.submit_name in request.POST
        data = request.POST if is_post else None
        form = forms.AuthenticationForm(data=data)
        is_secure = request.is_secure
        context = {
            'submit_name': self.submit_name,
        }
        seconds_to_wait = exponential_backoff.seconds_to_wait(request)
        reset = True
        if is_post and not seconds_to_wait:
            utils.csrf_token_check(request, form)
            reset = False
            if form.is_valid():
                if is_secure:
                    how = 'password-on-https'
                else:
                    how = 'password'
                exponential_backoff.success(request)
                return utils.login(request, form.get_user(), how)
            else:
                exponential_backoff.failure(request)
                seconds_to_wait = exponential_backoff.seconds_to_wait(request)
        if seconds_to_wait:
            # during a post reset form data to prevent validation
            if reset:
                form = forms.AuthenticationForm(initial={'username': data.get('username', '')})
            msg = _('You made too many login errors recently, you must wait <span class="js-seconds-until">%s</span> seconds to try again.')
            msg = msg % int(seconds_to_wait)
            utils.form_add_error(form, msg, safe=True)
        context['form'] = form
        return render(request, 'authentic2/login_password_form.html', context,
                context_instance=context_instance)

    def profile(self, request, *args, **kwargs):
        return views.login_password_profile(request, *args, **kwargs)
