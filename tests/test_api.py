# -*- coding: utf-8 -*-

import json
import pytest
import re
import urllib

from django.core.urlresolvers import reverse
from django.contrib.auth import get_user_model
from authentic2.a2_rbac.utils import get_default_ou
from django_rbac.utils import get_role_model
from authentic2.models import Service
from django.core import mail
from django.contrib.auth.hashers import check_password

from utils import login, basic_authorization_header

pytestmark = pytest.mark.django_db


def test_api_user_simple(logged_app):
    resp = logged_app.get('/api/user/')
    assert isinstance(resp.json, dict)
    assert 'username' in resp.json
    assert 'username' in resp.json


def test_api_user(client):
    # create an user, an ou role, a service and a service role
    ou = get_default_ou()

    User = get_user_model()
    user = User.objects.create(ou=ou, username='john.doe', first_name=u'Jôhn',
                               last_name=u'Doe', email='john.doe@example.net')
    user.set_password('password')
    user.save()

    Role = get_role_model()
    role1 = Role.objects.create(name='Role1', ou=ou)
    role1.members.add(user)

    service = Service.objects.create(name='Service1', slug='service1', ou=ou)
    role2 = Role.objects.create(name='Role2', service=service)
    role2.members.add(user)

    Role.objects.create(name='Role3', ou=ou)
    Role.objects.create(name='Role4', service=service)

    # test failure when unlogged
    response = client.get('/api/user/', HTTP_ORIGIN='http://testserver')
    assert response.content == '{}'

    # login
    client.login(username='john.doe', password='password')
    response = client.get('/api/user/', HTTP_ORIGIN='http://testserver')
    data = json.loads(response.content)
    assert isinstance(data, dict)
    assert set(data.keys()) == set(['uuid', 'username', 'first_name',
                                    'ou__slug', 'ou__uuid', 'ou__name',
                                    'last_name', 'email', 'roles', 'services',
                                    'is_superuser', 'ou'])
    assert data['uuid'] == user.uuid
    assert data['username'] == user.username
    assert data['first_name'] == user.first_name
    assert data['last_name'] == user.last_name
    assert data['email'] == user.email
    assert data['is_superuser'] == user.is_superuser
    assert data['ou'] == ou.name
    assert data['ou__name'] == ou.name
    assert data['ou__slug'] == ou.slug
    assert data['ou__uuid'] == ou.uuid
    assert isinstance(data['roles'], list)
    assert len(data['roles']) == 2
    for role in data['roles']:
        assert set(role.keys()) == set(['uuid', 'name', 'slug', 'is_admin',
                                        'is_service', 'ou__uuid', 'ou__name',
                                        'ou__slug'])
        assert (role['uuid'] == role1.uuid and
                role['name'] == role1.name and
                role['slug'] == role1.slug and
                role['is_admin'] is False and
                role['is_service'] is False and
                role['ou__uuid'] == ou.uuid and
                role['ou__name'] == ou.name and
                role['ou__slug'] == ou.slug) or \
               (role['uuid'] == role2.uuid and
                role['name'] == role2.name and
                role['slug'] == role2.slug and
                role['is_admin'] is False and
                role['is_service'] is True and
                role['ou__uuid'] == ou.uuid and
                role['ou__name'] == ou.name and
                role['ou__slug'] == ou.slug)

    assert isinstance(data['services'], list)
    assert len(data['services']) == 1
    s = data['services'][0]
    assert set(s.keys()) == set(['name', 'slug', 'ou', 'ou__name', 'ou__slug',
                                 'ou__uuid', 'roles'])
    assert s['name'] == service.name
    assert s['slug'] == service.slug
    assert s['ou'] == ou.name
    assert s['ou__name'] == ou.name
    assert s['ou__slug'] == ou.slug
    assert s['ou__uuid'] == ou.uuid
    assert isinstance(s['roles'], list)
    assert len(s['roles']) == 2
    for role in s['roles']:
        assert set(role.keys()) == set(['uuid', 'name', 'slug', 'is_admin',
                                        'is_service', 'ou__uuid', 'ou__name',
                                        'ou__slug'])
        assert (role['uuid'] == role1.uuid and
                role['name'] == role1.name and
                role['slug'] == role1.slug and
                role['is_admin'] is False and
                role['is_service'] is False and
                role['ou__uuid'] == ou.uuid and
                role['ou__name'] == ou.name and
                role['ou__slug'] == ou.slug) or \
               (role['uuid'] == role2.uuid and
                role['name'] == role2.name and
                role['slug'] == role2.slug and
                role['is_admin'] is False and
                role['is_service'] is True and
                role['ou__uuid'] == ou.uuid and
                role['ou__name'] == ou.name and
                role['ou__slug'] == ou.slug)


def test_api_users_list(app, user):
    app.authorization = ('Basic', (user.username, user.username))
    resp = app.get('/api/users/')
    assert isinstance(resp.json, dict)
    assert set(['count', 'previous', 'next', 'results']) == set(resp.json.keys())
    assert resp.json['previous'] is None
    assert resp.json['next'] is None
    if user.is_superuser:
        count = 7
    elif user.roles.exists():
        count = 2
    else:
        count = 0
    assert resp.json['count'] == count
    assert len(resp.json['results']) == count


def test_api_users_create(app, user):
    from django.contrib.auth import get_user_model
    from authentic2.models import Attribute, AttributeValue

    at = Attribute.objects.create(kind='title', name='title', label='title')

    app.authorization = ('Basic', (user.username, user.username))
    payload = {
        'ou': None,
        'username': 'john.doe',
        'first_name': 'John',
        'last_name': 'Doe',
        'email': 'john.doe@example.net',
        'password': 'password',
        'title': 'Mr',
    }
    if user.is_superuser:
        status = 201
    elif user.roles.exists():
        status = 201
        payload['ou'] = user.ou.slug
    else:
        status = 403

    resp = app.post_json('/api/users/', payload, status=status)
    if user.is_superuser or user.roles.exists():
        assert set(['ou', 'id', 'uuid', 'is_staff', 'is_superuser', 'first_name', 'last_name',
                    'date_joined', 'last_login', 'username', 'password', 'email', 'is_active',
                    'title']) == set(resp.json.keys())
        assert resp.json['first_name'] == payload['first_name']
        assert resp.json['last_name'] == payload['last_name']
        assert resp.json['email'] == payload['email']
        assert resp.json['username'] == payload['username']
        assert resp.json['title'] == payload['title']
        assert resp.json['uuid']
        assert resp.json['id']
        assert resp.json['date_joined']
        if user.is_superuser:
            assert resp.json['ou'] is None
        elif user.roles.exists():
            assert resp.json['ou'] == user.ou.slug
        new_user = get_user_model().objects.get(id=resp.json['id'])
        assert new_user.uuid == resp.json['uuid']
        assert new_user.username == resp.json['username']
        assert new_user.email == resp.json['email']
        assert new_user.first_name == resp.json['first_name']
        assert new_user.last_name == resp.json['last_name']
        assert AttributeValue.objects.with_owner(new_user).count() == 1
        assert AttributeValue.objects.with_owner(new_user)[0].attribute == at
        assert (json.loads(AttributeValue.objects.with_owner(new_user)[0].content) ==
                payload['title'])
        resp2 = app.get('/api/users/%s/' % resp.json['uuid'])
        assert resp.json == resp2.json
        payload.update({'uuid': '1234567890', 'email': 'foo@example.com',
                        'username': 'foobar'})
        resp = app.post_json('/api/users/', payload, status=status)
        assert resp.json['uuid'] == '1234567890'


def test_api_users_create_send_mail(app, settings, superuser):
    from authentic2.models import Attribute

    # Use case is often that Email is the main identifier
    settings.A2_EMAIL_IS_UNIQUE = True
    Attribute.objects.create(kind='title', name='title', label='title')

    app.authorization = ('Basic', (superuser.username, superuser.username))
    payload = {
        'ou': None,
        'username': 'john.doe',
        'first_name': 'John',
        'last_name': 'Doe',
        'email': 'john.doe@example.net',
        'title': 'Mr',
        'send_registration_email': True,
    }
    assert len(mail.outbox) == 0
    resp = app.post_json('/api/users/', payload, status=201)
    user_id = resp.json['id']
    assert len(mail.outbox) == 1
    # Follow activation link
    assert re.findall('http://[^ ]*/', mail.outbox[0].body)
    url = re.findall('http://[^ ]*/', mail.outbox[0].body)[0]
    relative_url = url.split('localhost:80')[1]
    print relative_url
    resp = app.get(relative_url, status=200)
    resp.form.set('new_password1', '1234aA')
    resp.form.set('new_password2', '1234aA')
    resp = resp.form.submit().follow()
    # Check user was properly logged in
    assert str(app.session['_auth_user_id']) == str(user_id)


def test_api_users_create_force_password_reset(app, client, settings, superuser):
    app.authorization = ('Basic', (superuser.username, superuser.username))
    payload = {
        'ou': None,
        'username': 'john.doe',
        'first_name': 'John',
        'last_name': 'Doe',
        'email': 'john.doe@example.net',
        'password': '1234',
        'force_password_reset': True,
    }
    app.post_json('/api/users/', payload, status=201)
    # Verify password reset is enforced on next login
    resp = login(app, 'john.doe', path='/', password='1234').follow()
    resp.form.set('old_password', '1234')
    resp.form.set('new_password1', '1234aB')
    resp.form.set('new_password2', '1234aB')
    resp = resp.form.submit('Submit').follow()
    assert 'Password changed' in resp


def test_api_role_add_member(app, user, role, member):
    app.authorization = ('Basic', (user.username, user.username))
    payload = {
        'role_uuid': role.uuid,
        'role_member': member.uuid
    }

    authorized = user.has_perm('a2_rbac.change_role', role)

    if member.username == 'fake' or role.name == 'fake':
        status = 404
    elif authorized:
        status = 201
    else:
        status = 403

    resp = app.post_json('/api/roles/{0}/members/{1}/'.format(role.uuid, member.uuid), payload,
                         status=status)
    if status == 404:
        pass
    elif authorized:
        assert resp.json['detail'] == 'User successfully added to role'
    else:
        assert resp.json['detail'] == 'User not allowed to change role'


def test_api_role_remove_member(app, user, role, member):
    app.authorization = ('Basic', (user.username, user.username))

    authorized = user.is_superuser or user.has_perm('a2_rbac.change_role', role)

    if member.username == 'fake' or role.name == 'fake':
        status = 404
    elif authorized:
        status = 200
    else:
        status = 403

    resp = app.delete_json('/api/roles/{0}/members/{1}/'.format(role.uuid, member.uuid),
                           status=status)

    if status == 404:
        pass
    elif authorized:
        assert resp.json['detail'] == 'User successfully removed from role'
    else:
        assert resp.json['detail'] == 'User not allowed to change role'


def test_register_no_email_validation(app, admin, django_user_model):
    User = django_user_model
    password = '12XYab'
    username = 'john.doe'
    email = 'john.doe@example.com'
    first_name = 'John'
    last_name = 'Doe'
    return_url = 'http://sp.example.com/validate/'

    # invalid payload
    payload = {
        'last_name': last_name,
        'return_url': return_url,
    }
    headers = basic_authorization_header(admin)
    assert len(mail.outbox) == 0
    response = app.post_json(reverse('a2-api-register'), payload, headers=headers, status=400)
    assert 'errors' in response.json
    assert response.json['result'] == 0
    assert response.json['errors'] == {
        '__all__': ['You must set at least a username, an email or a first name and a last name'],
    }

    # valid payload
    payload = {
        'username': username,
        'email': email,
        'first_name': first_name,
        'last_name': last_name,
        'password': password,
        'no_email_validation': True,
        'return_url': return_url,
    }
    assert len(mail.outbox) == 0
    response = app.post_json(reverse('a2-api-register'), payload, headers=headers)
    assert len(mail.outbox) == 0
    assert response.status_code == 201
    assert response.json['result'] == 1
    assert response.json['user']['username'] == username
    assert response.json['user']['email'] == email
    assert response.json['user']['first_name'] == first_name
    assert response.json['user']['last_name'] == last_name
    assert check_password(password, response.json['user']['password'])
    assert response.json['token']
    assert response.json['validation_url'].startswith('http://localhost:80/accounts/activate/')
    assert User.objects.count() == 2
    user = User.objects.latest('id')
    assert user.username == username
    assert user.email == email
    assert user.first_name == first_name
    assert user.last_name == last_name
    assert user.check_password(password)

def test_register_ou_no_email_validation(app, admin, django_user_model):
    User = django_user_model
    password = '12XYab'
    username = 'john.doe'
    email = 'john.doe@example.com'
    first_name = 'John'
    last_name = 'Doe'
    return_url = 'http://sp.example.com/validate/'
    ou = 'default'

    # invalid payload
    payload = {
        'last_name': last_name,
        'return_url': return_url,
    }
    headers = basic_authorization_header(admin)
    assert len(mail.outbox) == 0
    response = app.post_json(reverse('a2-api-register'), payload, headers=headers, status=400)
    assert 'errors' in response.json
    assert response.json['result'] == 0
    assert response.json['errors'] == {
        '__all__': ['You must set at least a username, an email or a first name and a last name'],
    }

    # valid payload
    payload = {
        'username': username,
        'email': email,
        'first_name': first_name,
        'last_name': last_name,
        'password': password,
        'no_email_validation': True,
        'return_url': return_url,
        'ou': ou,
    }
    assert len(mail.outbox) == 0
    response = app.post_json(reverse('a2-api-register'), payload, headers=headers)
    assert len(mail.outbox) == 0
    assert response.status_code == 201
    print response.json
    assert response.json['result'] == 1
    assert response.json['user']['username'] == username
    assert response.json['user']['email'] == email
    assert response.json['user']['first_name'] == first_name
    assert response.json['user']['last_name'] == last_name
    assert check_password(password, response.json['user']['password'])
    assert response.json['token']
    assert response.json['validation_url'].startswith('http://localhost:80/accounts/activate/')
    assert User.objects.count() == 2
    user = User.objects.latest('id')
    assert user.username == username
    assert user.email == email
    assert user.first_name == first_name
    assert user.last_name == last_name
    assert user.check_password(password)
