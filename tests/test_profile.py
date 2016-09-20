import re

import pytest

from django.core import mail
from django.core.urlresolvers import reverse

from authentic2.models import Attribute, AttributeValue

import utils

pytestmark = pytest.mark.django_db


def test_send_password_reset_email(app, simple_user):
    from authentic2.utils import send_password_reset_mail
    assert len(mail.outbox) == 0
    send_password_reset_mail(simple_user,
                            legacy_subject_templates=['registration/password_reset_subject.txt'],
                            legacy_body_templates=['registration/password_reset_email.html'],
                            context={
                               'base_url': 'http://localhost:80',
                            })
    assert len(mail.outbox) == 1
    body = mail.outbox[0].body
    assert re.findall('http://[^ ]*/', body)
    url = re.findall('http://[^ ]*/', body)[0]
    relative_url = url.split('localhost:80')[1]
    resp = app.get(relative_url, status=200)
    resp.form.set('new_password1', '1234aA')
    resp.form.set('new_password2', '1234aA')
    resp = resp.form.submit().follow()
    assert str(app.session['_auth_user_id']) == str(simple_user.pk)

def test_password_reset_view(app, simple_user):
    url = reverse('password_reset') + '?next=/'
    resp = app.get(url, status=200)
    resp.form.set('email', simple_user.email)
    assert len(mail.outbox) == 0
    resp = resp.form.submit().follow().follow()
    assert len(mail.outbox) == 1
    assert 'a2-login-forms' in resp
    body = mail.outbox[0].body
    assert re.findall('http://[^ ]*/', body)
    url = re.findall('http://[^ ]*/', body)[0]
    relative_url = url.split('localhost:80')[1]
    resp = app.get(relative_url, status=200)
    resp.form.set('new_password1', '1234aA')
    resp.form.set('new_password2', '1234aA')
    resp = resp.form.submit().follow()
    assert str(app.session['_auth_user_id']) == str(simple_user.pk)

def test_account_edit_view(app, simple_user):
    utils.login(app, simple_user)
    url = reverse('profile_edit')
    resp = app.get(url, status=200)

    attribute = Attribute.objects.create(name='phone', label='phone',
            kind='string', user_visible=True, user_editable=True)
    resp = app.get(url, status=200)
    resp.form.set('edit-profile-phone', '0123456789')
    resp = resp.form.submit().follow()
    assert attribute.get_value(simple_user) == '0123456789'

    attribute.set_value(simple_user, '0123456789', verified=True)
    resp = app.get(url, status=200)
    resp.form.set('edit-profile-phone', '1234567890')
    assert 'readonly' in resp.form['edit-profile-phone'].attrs
    resp = resp.form.submit().follow()
    assert attribute.get_value(simple_user) == '0123456789'

    resp = app.get(url, status=200)
    assert 'phone' in resp
    assert 'readonly' in resp.form['edit-profile-phone'].attrs

    attribute.disabled = True
    attribute.save()
    resp = app.get(url, status=200)
    assert 'phone' not in resp
    assert attribute.get_value(simple_user) == '0123456789'
