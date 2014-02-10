from django.contrib.auth import REDIRECT_FIELD_NAME
from django.http import HttpResponseRedirect
from django.utils.http import urlencode
from django.template import RequestContext
from django.template.loader import render_to_string

from authentic2.auth2_auth import NONCE_FIELD_NAME


def login_password_profile(request, next):
    return render_to_string('auth/login_password_profile.html', {},
            RequestContext(request))


def redirect_to_login(request, next=None, nonce=None, keep_qs=False):
    '''Redirect to the login, eventually adding a nonce'''
    if next is None:
        if keep_qs:
            next = request.get_full_path()
        else:
            next = request.path
    qs = { REDIRECT_FIELD_NAME: next }
    if nonce is not None:
        qs.update({ NONCE_FIELD_NAME: nonce })
    return HttpResponseRedirect('/login?%s' % urlencode(qs))
