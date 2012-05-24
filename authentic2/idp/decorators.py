from django.contrib.auth.decorators import login_required
from django.http import HttpResponseRedirect
from functools import wraps
from django.utils.translation import ugettext as _

from authentic2.authsaml2.models import SAML2TransientUser

TRANSIENT_USER_TYPES = (SAML2TransientUser, )

def prevent_access_to_transient_users(view_func):

    def _wrapped_view(request, *args, **kwargs):
        '''Test if the user is transient'''
        for user_type in TRANSIENT_USER_TYPES:
            if isinstance(request.user, user_type):
                return HttpResponseRedirect('/')
        return view_func(request, *args, **kwargs)
    return login_required(wraps(view_func)(_wrapped_view))
