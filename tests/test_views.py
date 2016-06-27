from utils import login
import pytest

from django.core.urlresolvers import reverse

from authentic2.custom_user.models import User

pytestmark = pytest.mark.django_db


def test_profile(app, simple_user):
    page = login(app, simple_user, path=reverse('account_management'))
    assert simple_user.first_name in page
    assert simple_user.last_name in page


def test_account_delete(app, simple_user):
    assert simple_user.is_active
    page = login(app, simple_user, path=reverse('delete_account'))
    page.form.set('password', simple_user.username)
    # FIXME: webtest does not set the Referer header, so the logout page will always ask for
    # confirmation under tests
    response = page.form.submit(name='submit').follow()
    response = response.form.submit()
    assert not User.objects.get(pk=simple_user.pk).is_active
    assert response.location == 'http://localhost:80/'
    response = response.follow().follow()
    assert response.request.url.startswith('http://localhost/login/')


def test_login_invalid_next(app):
    app.get(reverse('auth_login') + '?next=plop')
