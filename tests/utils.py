import base64

import pytest

from django.core.urlresolvers import reverse
from django.conf import settings
import sqlite3


skipif_no_partial_index = pytest.mark.skipif(
    sqlite3.sqlite_version_info < (3, 8) and 'sqlite' in settings.DATABASES['default']['ENGINE'],
    reason='partial indexes do not work with sqlite < 3.8')


def login(app, user, path=None, password=None):
    if path:
        login_page = app.get(path, status=302).follow()
    else:
        login_page = app.get(reverse('auth_login'))
    assert login_page.request.path == reverse('auth_login')
    form = login_page.form
    form.set('username', user.username if hasattr(user, 'username') else user)
    # password is supposed to be the same as username
    form.set('password', password or user.username)
    response = form.submit(name='login-password-submit').follow()
    if path:
        assert response.request.path == path
    else:
        assert response.request.path == reverse('auth_homepage')
    assert '_auth_user_id' in app.session
    return response

def basic_authorization_header(user, password=None):
    cred = base64.b64encode('%s:%s' % (user.username, password or user.username))
    return {'Authorization': 'Basic %s' % cred}
