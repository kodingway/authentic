from django.contrib.auth import authenticate, login


from . import util, app_settings


class SSLAuthMiddleware(object):
    """
    attempts to find a valid user based on the client certificate info
    """
    def process_request(self, request):
        if app_settings.USE_COOKIE and request.user.is_authenticated():
            return
        ssl_info  = util.SSLInfo(request)
        user = authenticate(ssl_info=ssl_info)
        if user and request.user != user:
            login(request, user)
