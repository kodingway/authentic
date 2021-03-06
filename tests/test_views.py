from utils import login
import pytest

from django.core.urlresolvers import reverse
from django.core import mail

from authentic2.custom_user.models import User

pytestmark = pytest.mark.django_db


def test_profile(app, simple_user):
    page = login(app, simple_user, path=reverse('account_management'))
    assert simple_user.first_name in page
    assert simple_user.last_name in page


def test_email_change(app, simple_user):
    page = login(app, simple_user, path=reverse('email-change'))
    page = page.form.submit('cancel').follow()

    page = app.get(reverse('email-change'))
    page.form.set('email', 'john.doe2@example.net')
    page.form.set('password', simple_user.username)
    page = page.form.submit('Validate').follow()
    assert len(mail.outbox) == 1
    assert 'for 2 hours.' in mail.outbox[0].body


def test_password_change(app, simple_user):
    page = login(app, simple_user, path=reverse('auth_password_change'))
    page = page.form.submit('cancel').follow()


def test_account_delete(app, simple_user):
    assert simple_user.is_active
    page = login(app, simple_user, path=reverse('delete_account'))
    page.form.set('password', simple_user.username)
    # FIXME: webtest does not set the Referer header, so the logout page will always ask for
    # confirmation under tests
    response = page.form.submit(name='submit').follow()
    response = response.form.submit()
    assert not User.objects.get(pk=simple_user.pk).is_active
    assert response.location == 'http://testserver/'
    response = response.follow().follow()
    assert response.request.url.startswith('http://testserver/login/')


def test_login_invalid_next(app):
    app.get(reverse('auth_login') + '?next=plop')
