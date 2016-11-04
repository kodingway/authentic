import re
import pytest

from django.core.urlresolvers import reverse
from django.core import mail

from django_rbac.utils import get_ou_model, get_role_model
from utils import login

pytestmark = pytest.mark.django_db


def test_manager_login(superuser_or_admin, app):
    manager_home_page = login(app, superuser_or_admin, reverse('a2-manager-homepage'))
    for section in ('users', 'roles', 'ous', 'services'):
        path = reverse('a2-manager-%s' % section)
        assert manager_home_page.pyquery.remove_namespaces()('.apps a[href=\'%s\']' % path)


def test_manager_create_ou(superuser_or_admin, app):
    OU = get_ou_model()

    ou_add = login(app, superuser_or_admin, path=reverse('a2-manager-ou-add'))
    form = ou_add.form
    form.set('name', 'New OU')
    response = form.submit().follow()
    assert 'New OU' in response
    assert OU.objects.count() == 2
    assert OU.objects.get(name='New OU').slug == 'new-ou'

    # Test slug collision
    OU.objects.filter(name='New OU').update(name='Old OU')
    response = form.submit().follow()
    assert 'Old OU' in response
    assert 'New OU' in response
    assert OU.objects.get(name='Old OU').slug == 'new-ou'
    assert OU.objects.get(name='New OU').slug == 'new-ou1'
    assert OU.objects.count() == 3


def test_manager_create_role(migrations, superuser_or_admin, app):
    Role = get_role_model()
    OU = get_ou_model()

    non_admin_roles = Role.objects.exclude(slug__startswith='_')

    ou_add = login(app, superuser_or_admin, reverse('a2-manager-role-add'))
    form = ou_add.form
    assert 'name' in form.fields
    assert 'description' in form.fields
    assert 'ou' not in form.fields
    form.set('name', 'New role')
    response = form.submit().follow()
    assert non_admin_roles.count() == 1
    role = non_admin_roles.get()
    assert response.request.path == reverse('a2-manager-role-members', kwargs={'pk': role.pk})
    role_list = app.get(reverse('a2-manager-roles'))
    assert 'New role' in role_list 

    # Test slug collision
    non_admin_roles.update(name='Old role')
    response = form.submit().follow()
    role_list = app.get(reverse('a2-manager-roles'))
    assert 'New role' in role_list 
    assert 'Old role' in role_list
    assert non_admin_roles.count() == 2
    assert non_admin_roles.get(name='New role').slug == 'new-role1'
    assert non_admin_roles.get(name='Old role').slug == 'new-role'

    # Test multi-ou form
    ou = OU.objects.create(name='New OU', slug='new-ou')
    ou_add = app.get(reverse('a2-manager-role-add'))
    form = ou_add.form
    assert 'name' in form.fields
    assert 'description' in form.fields
    assert 'ou' in form.fields
    options = [o[2] for o in form.fields['ou'][0].options]
    assert len(options) == 3
    assert '---------' in options
    assert 'New OU' in options

def test_manager_user_password_reset(app, superuser, simple_user):
    resp = login(app, superuser, reverse('a2-manager-user-edit',
                                                  kwargs={'pk': simple_user.pk}))
    assert len(mail.outbox) == 0
    resp = resp.form.submit('password_reset')
    assert 'A mail was sent to' in resp
    assert len(mail.outbox) == 1
    body = mail.outbox[0].body
    assert re.findall('http://[^ ]*/', body)
    url = re.findall('http://[^ ]*/', body)[0]
    relative_url = url.split('localhost')[1]
    resp = app.get('/logout/').maybe_follow()
    resp = app.get(relative_url, status=200)
    resp.form.set('new_password1', '1234aA')
    resp.form.set('new_password2', '1234aA')
    resp = resp.form.submit().follow()
    assert str(app.session['_auth_user_id']) == str(simple_user.pk)
