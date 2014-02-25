from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import login
from django.utils.translation import gettext_noop
from django.http import HttpResponseRedirect

from . import views, models

class LoginPasswordBackend(object):
    def enabled(self):
        return True

    def name(self):
        return gettext_noop('Password')

    def id(self):
        return 'password'

    def form(self):
        return AuthenticationForm

    def post(self, request, form, nonce, next):
        # Login the user
        login(request, form.get_user())
        # Keep a trace
        if 'HTTPS' in request.environ.get('HTTPS','').lower() == 'on':
            how = 'password-on-https'
        else:
            how = 'password'
        if nonce:
            user = form.get_user()
            if hasattr(user, 'USERNAME_FIELD'):
                username = getattr(user, user.USERNAME_FIELD)
            else:
                username = user.username
            models.AuthenticationEvent(who=unicode(username)[:80], how=how,
                    nonce=nonce).save()
        return HttpResponseRedirect(next)

    def template(self):
        return 'auth/login_form.html'

    def profile(self, request):
        return views.login_password_profile(request)
