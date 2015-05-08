# PermWrapper and PermLookupDict proxy the permissions system into objects that
# the template system can understand.

from django.contrib.auth.context_processors import PermWrapper as AuthPermWrapper

class PermAnyLookupDict(object):
    def __init__(self, user, app_label):
        self.user = user
        self.app_label = app_label

    def __iter__(self):
        # I am large, I contain multitudes.
        raise TypeError("PermAnyLookupDict is not iterable.")

    def __getitem__(self, perm_name):
        return self.user.has_perm_any('%s.%s' % (self.app_label, perm_name))

    def __bool__(self):
        raise TypeError('PermAnyLookupDict has not boolean value')

class PermAnyWrapper(object):
    def __init__(self, user):
        self.user = user

    def __getitem__(self, app_label):
        return PermAnyLookupDict(self.user, app_label)

    def __iter__(self):
        # I am large, I contain multitudes.
        raise TypeError("PermAnyWrapper is not iterable.")

    def __bool__(self):
        raise TypeError('PermAnyWrapper has not boolean value')

    def __nonzero__(self):      # Python 2 compatibility
        return type(self).__bool__(self)

class PermWrapper(AuthPermWrapper):
    def __getitem__(self, app_label):
        if app_label == 'any':
            return PermAnyWrapper(self.user)
        return super(PermWrapper, self).__getitem__(app_label)

def auth(request):
    """
    Returns context variables required by apps that use Django's authentication
    system.

    If there is no 'user' attribute in the request, uses AnonymousUser (from
    django.contrib.auth).
    """
    if hasattr(request, 'user'):
        user = request.user
    else:
        from django.contrib.auth.models import AnonymousUser
        user = AnonymousUser()

    return {
        'user': user,
        'perms': PermWrapper(user),
    }
