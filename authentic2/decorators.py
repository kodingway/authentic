from django.contrib.auth.decorators import login_required
from django.http import HttpResponseRedirect
from functools import wraps

TRANSIENT_USER_TYPES = []

def is_transient_user(user):
    return isinstance(user, tuple(TRANSIENT_USER_TYPES))

def prevent_access_to_transient_users(view_func):
    def _wrapped_view(request, *args, **kwargs):
        '''Test if the user is transient'''
        for user_type in TRANSIENT_USER_TYPES:
            if is_transient_user(request.user):
                return HttpResponseRedirect('/')
        return view_func(request, *args, **kwargs)
    return login_required(wraps(view_func)(_wrapped_view))
