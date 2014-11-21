import urllib

from django.utils.translation import gettext_noop
from django.http import HttpResponseRedirect
from django.contrib.auth import REDIRECT_FIELD_NAME
import django.forms


from authentic2.constants import NONCE_FIELD_NAME


from . import views, app_settings


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
        if next_url is None:
            next_url = request.path
        qs = { REDIRECT_FIELD_NAME: next_url }
        if nonce is not None:
            qs.update({ NONCE_FIELD_NAME: nonce })
        return HttpResponseRedirect('/sslauth?%s' % urllib.urlencode(qs))

    def template(self):
        return 'auth/login_form_ssl.html'

    def profile(self, request, *args, **kwargs):
        return views.profile(request, *args, **kwargs)
