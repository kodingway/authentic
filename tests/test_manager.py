import re
import pytest

from django.core.urlresolvers import reverse
from django.core import mail

from authentic2.a2_rbac.utils import get_default_ou

from django_rbac.utils import get_ou_model, get_role_model
from django.contrib.auth import get_user_model
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


def test_manager_create_role(superuser_or_admin, app):
    # clear cache from previous runs
    from authentic2.manager.utils import get_ou_count
    get_ou_count.cache.cache = {}

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
    OU.objects.create(name='New OU', slug='new-ou')
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
    resp = login(app, superuser,
                 reverse('a2-manager-user-detail', kwargs={'pk': simple_user.pk}))
    assert len(mail.outbox) == 0
    resp = resp.form.submit('password_reset')
    assert 'A mail was sent to' in resp
    assert len(mail.outbox) == 1
    body = mail.outbox[0].body
    assert re.findall('http://[^ ]*/', body)
    url = re.findall('http://[^ ]*/', body)[0]
    relative_url = url.split('testserver')[1]
    resp = app.get('/logout/').maybe_follow()
    resp = app.get(relative_url, status=200)
    resp.form.set('new_password1', '1234==aA')
    resp.form.set('new_password2', '1234==aA')
    resp = resp.form.submit().follow()
    assert str(app.session['_auth_user_id']) == str(simple_user.pk)


def test_manager_user_edit_by_uuid(app, superuser, simple_user):
    url = reverse('a2-manager-user-by-uuid-edit', kwargs={'slug': simple_user.uuid})
    resp = login(app, superuser, url)
    assert simple_user.first_name.encode('utf-8') in resp.content


def test_manager_stress_create_user(superuser_or_admin, app, mailoutbox):
    User = get_user_model()
    OU = get_ou_model()

    new_ou = OU.objects.create(name='new ou', slug='new-ou')
    url = reverse('a2-manager-user-add', kwargs={'ou_pk': new_ou.pk})
    # create first user with john.doe@gmail.com ou OU1 : OK

    assert len(mailoutbox) == 0
    assert User.objects.filter(ou_id=new_ou.id).count() == 0
    for i in range(100):
        ou_add = login(app, superuser_or_admin, url)
        form = ou_add.form
        form.set('first_name', 'John')
        form.set('last_name', 'Doe')
        form.set('email', 'john.doe@gmail.com')
        form.set('password1', 'password')
        form.set('password2', 'password')
        form.submit().follow()
        app.get('/logout/').form.submit()
    assert User.objects.filter(ou_id=new_ou.id).count() == 100
    assert len(mailoutbox) == 100


def test_role_members_from_ou(app, superuser, settings):
    Role = get_role_model()
    r = Role.objects.create(name='role', slug='role', ou=get_default_ou())
    url = reverse('a2-manager-role-members', kwargs={'pk': r.pk})
    response = login(app, superuser, url)
    assert not response.context['form'].fields['user'].queryset.query.where
    settings.A2_MANAGER_ROLE_MEMBERS_FROM_OU = True
    response = app.get(url)
    assert response.context['form'].fields['user'].queryset.query.where
