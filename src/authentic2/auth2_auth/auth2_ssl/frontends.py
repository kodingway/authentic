from django.utils.translation import gettext_noop
import django.forms

from . import views, app_settings
from authentic2.utils import redirect_to_login


class SSLFrontend(object):
    def enabled(self):
        return app_settings.ENABLE

    def id(self):
        return 'ssl'

    def name(self):
        return gettext_noop('SSL with certificates')

    def form(self):
        return django.forms.Form

    def post(self, request, form, nonce, next_url):
        return redirect_to_login(request, login_url='user_signin_ssl',)

    def template(self):
        return 'auth/login_form_ssl.html'

    def profile(self, request, *args, **kwargs):
        return views.profile(request, *args, **kwargs)
