from django.contrib.auth import authenticate, login, get_user
from django.contrib.auth.models import AnonymousUser


from . import util, app_settings, backends


class SSLAuthMiddleware(object):
    """
    attempts to find a valid user based on the client certificate info
    """
    def process_request(self, request):

        USE_COOKIE = app_settings.USE_COOKIE

        if USE_COOKIE:
            request.user = get_user(request)
            if request.user.is_authenticated():
                return

        ssl_info  = util.SSLInfo(request)
        user = authenticate(ssl_info=ssl_info) or AnonymousUser()

        if not user.is_authenticated() and ssl_info.verify \
                and app_settings.CREATE_USER:
            if backends.SSLAuthBackend().create_user(ssl_info):
                user = authenticate(ssl_info=ssl_info) or AnonymousUser()

        if user.is_authenticated() and USE_COOKIE:
            login(request, user)
        else:
            request.user = user
