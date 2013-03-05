import urllib
import random
import base64

from django.http import HttpResponseBadRequest, HttpResponseRedirect
from django.template import RequestContext
from django.template.loader import render_to_string

import models
import authentic2.vendor.totp_js.totp_bookmarklet as totp_bookmarklet

_hexachars = '0123456789abcdef'

def new_totp_secret(request, next_url='/'):
    if request.user is None or not hasattr(request.user, '_meta') \
       or request.method != 'POST':
        return HttpResponseBadRequest()
    key = ''.join([random.choice(_hexachars) for x in range(40)])
    secret, _ = models.OATHTOTPSecret.objects.get_or_create(user=request.user)
    secret.key = key
    secret.save()
    next_url = request.REQUEST.get('next', next_url)
    return HttpResponseRedirect(next_url)

def delete_totp_secret(request, next_url='/'):
    if request.user is None or not hasattr(request.user, '_meta') \
       or request.method != 'POST':
        return HttpResponseBadRequest()
    try:
        models.OATHTOTPSecret.objects.filter(user=request.user).delete()
    except models.OATHTOTPSecret.DoesNotExist:
        pass
    next_url = request.REQUEST.get('next', next_url)
    return HttpResponseRedirect(next_url)

def totp_profile(request, next_url='', template_name='oath/totp_profile.html'):
    if request.user is None or not hasattr(request.user, '_meta'):
        return ''
    if next_url:
        next_url = '?next=%s' % urllib.quote(next_url)
    google_authenticator, key, bookmarklet = '', '', ''
    try:
        secret = models.OATHTOTPSecret.objects.get(user=request.user)
        key = secret.key
        bookmarklet = totp_bookmarklet.otp_doc(secret.key)
        google_authenticator = 'otpauth://totp/%(user)s@localhost?secret=%(b32_secret)s' % \
                { 'user': request.user.username,
                  'domain': request.get_host(),
                  'b32_secret': base64.b32encode(key.decode('hex')) }
    except models.OATHTOTPSecret.DoesNotExist:
        pass
    return render_to_string(template_name,
            { 'key': key, 
              'bookmarklet': bookmarklet, 
              'google_authenticator': google_authenticator,
              'next': next_url,
              'base': '/oath'},
            RequestContext(request))
