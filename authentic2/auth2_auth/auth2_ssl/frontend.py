import urllib

from django.utils.translation import gettext_noop
from django.http import HttpResponseRedirect
from django.contrib.auth import REDIRECT_FIELD_NAME
import django.forms


from authentic2.constants import NONCE_FIELD_NAME


from . import views


class SSLFrontend(object):
    def enabled(self):
        return True

    def id(self):
        return 'ssl'

    def name(self):
        return gettext_noop('SSL with certificates')

    def form(self):
        return django.forms.Form

    def post(self, request, form, nonce, next):
        if next is None:
            next = request.path
        qs = { REDIRECT_FIELD_NAME: next }
        if nonce is not None:
            qs.update({ NONCE_FIELD_NAME: nonce })
        return HttpResponseRedirect('/sslauth?%s' % urllib.urlencode(qs))

    def template(self):
        return 'auth/login_form_ssl.html'

    def profile(self, request, next=None):
        return views.profile(request)
