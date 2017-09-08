# -*- coding: utf-8 -*-

import json
import pytest
import re
import random
import uuid


from django.core.urlresolvers import reverse
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from authentic2.a2_rbac.utils import get_default_ou
from django_rbac.utils import get_role_model, get_ou_model
from django_rbac.models import SEARCH_OP
from authentic2.models import Service
from django.core import mail
from django.contrib.auth.hashers import check_password

from authentic2_idp_oidc.models import OIDCClient

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
    assert set(['previous', 'next', 'results']) == set(resp.json.keys())
    assert resp.json['previous'] is None
    assert resp.json['next'] is None


def test_api_users_create(settings, app, api_user):
    from django.contrib.auth import get_user_model
    from authentic2.models import Attribute, AttributeValue

    at = Attribute.objects.create(kind='title', name='title', label='title')
    app.authorization = ('Basic', (api_user.username, api_user.username))
    # test missing first_name
    payload = {
        'username': 'john.doe',
        'email': 'john.doe@example.net',
    }
    if api_user.roles.exists():
        status = 400
        payload['ou'] = api_user.ou.slug
    resp = app.post_json('/api/users/', params=payload, status=400)
    assert resp.json['result'] == 0
    assert set(['first_name', 'last_name']) == set(resp.json['errors'])
    settings.A2_API_USERS_REQUIRED_FIELDS = ['email']
    if api_user.is_superuser or hasattr(api_user, 'oidc_client') or api_user.roles.exists():
        status = 201
    else:
        status = 403
    resp = app.post_json('/api/users/', params=payload, status=status)
    if status == 201:
        assert resp.json
    del settings.A2_API_USERS_REQUIRED_FIELDS

    payload = {
        'username': 'john.doe',
        'first_name': 'John',
        'last_name': 'Doe',
        'email': 'john.doe@example.net',
        'password': 'password',
        'title': 'Mr',
    }
    if api_user.is_superuser:
        status = 201
    elif api_user.roles.exists():
        status = 201
        payload['ou'] = api_user.ou.slug
    else:
        status = 403

    resp = app.post_json('/api/users/', params=payload, status=status)
    if api_user.is_superuser or api_user.roles.exists():
        assert set(['ou', 'id', 'uuid', 'is_staff', 'is_superuser', 'first_name', 'last_name',
                    'date_joined', 'last_login', 'username', 'password', 'email', 'is_active',
                    'title', 'modified', 'email_verified']) == set(resp.json.keys())
        assert resp.json['first_name'] == payload['first_name']
        assert resp.json['last_name'] == payload['last_name']
        assert resp.json['email'] == payload['email']
        assert resp.json['username'] == payload['username']
        assert resp.json['title'] == payload['title']
        assert resp.json['uuid']
        assert resp.json['id']
        assert resp.json['date_joined']
        if api_user.is_superuser:
            assert resp.json['ou'] == 'default'
        elif api_user.roles.exists():
            assert resp.json['ou'] == api_user.ou.slug
        new_user = get_user_model().objects.get(id=resp.json['id'])
        assert new_user.uuid == resp.json['uuid']
        assert new_user.username == resp.json['username']
        assert new_user.email == resp.json['email']
        assert new_user.first_name == resp.json['first_name']
        assert new_user.last_name == resp.json['last_name']
        assert AttributeValue.objects.with_owner(new_user).count() == 3
        assert AttributeValue.objects.with_owner(new_user).filter(attribute=at).exists()
        assert (AttributeValue.objects.with_owner(new_user).get(attribute=at).content ==
                payload['title'])
        resp2 = app.get('/api/users/%s/' % resp.json['uuid'])
        assert resp.json == resp2.json
        payload.update({'uuid': '1234567890', 'email': 'foo@example.com',
                        'username': 'foobar'})
        resp = app.post_json('/api/users/', params=payload, status=status)
        assert resp.json['uuid'] == '1234567890'
        assert 'title' in resp.json
        at.disabled = True
        at.save()
        resp = app.get('/api/users/1234567890/')
        assert 'title' not in resp.json


def test_api_users_create_email_is_unique(settings, app, superuser):
    from django.contrib.auth import get_user_model

    User = get_user_model()
    OU = get_ou_model()
    ou1 = OU.objects.create(name='OU1', slug='ou1')
    ou2 = OU.objects.create(name='OU2', slug='ou2', email_is_unique=True)

    app.authorization = ('Basic', (superuser.username, superuser.username))
    # test missing first_name
    payload = {
        'ou': 'ou1',
        'first_name': 'John',
        'last_name': 'Doe',
        'email': 'john.doe@example.net',
    }

    assert User.objects.filter(ou=ou1).count() == 0
    assert User.objects.filter(ou=ou2).count() == 0

    app.post_json('/api/users/', params=payload)
    assert User.objects.filter(ou=ou1).count() == 1

    app.post_json('/api/users/', params=payload)
    assert User.objects.filter(ou=ou1).count() == 2

    payload['ou'] = 'ou2'
    app.post_json('/api/users/', params=payload)
    assert User.objects.filter(ou=ou2).count() == 1

    resp = app.post_json('/api/users/', params=payload, status=400)
    assert User.objects.filter(ou=ou2).count() == 1
    assert resp.json['result'] == 0
    assert resp.json['errors']['email']

    settings.A2_EMAIL_IS_UNIQUE = True
    User.objects.filter(ou=ou1).delete()
    assert User.objects.filter(ou=ou1).count() == 0
    payload['ou'] = 'ou1'
    app.post_json('/api/users/', params=payload, status=400)
    assert User.objects.filter(ou=ou1).count() == 0
    assert resp.json['result'] == 0
    assert resp.json['errors']['email']

    payload['email'] = 'john.doe2@example.net'
    resp = app.post_json('/api/users/', params=payload)
    uuid = resp.json['uuid']

    app.patch_json('/api/users/%s/' % uuid, params={'email': 'john.doe3@example.net'})
    resp = app.patch_json('/api/users/%s/' % uuid, params={'email': 'john.doe@example.net'},
                          status=400)
    assert resp.json['result'] == 0
    assert resp.json['errors']['email']
    settings.A2_EMAIL_IS_UNIQUE = False

    payload['ou'] = 'ou2'
    payload['email'] = 'john.doe2@example.net'
    resp = app.post_json('/api/users/', params=payload)
    assert User.objects.filter(ou=ou2).count() == 2
    uuid = resp.json['uuid']
    resp = app.patch_json('/api/users/%s/' % uuid, params={'email': 'john.doe@example.net'},
                          status=400)
    assert resp.json['result'] == 0
    assert resp.json['errors']['email']


def test_api_users_create_send_mail(app, settings, superuser):
    from authentic2.models import Attribute

    # Use case is often that Email is the main identifier
    settings.A2_EMAIL_IS_UNIQUE = True
    Attribute.objects.create(kind='title', name='title', label='title')

    app.authorization = ('Basic', (superuser.username, superuser.username))
    payload = {
        'username': 'john.doe',
        'first_name': 'John',
        'last_name': 'Doe',
        'email': 'john.doe@example.net',
        'title': 'Mr',
        'send_registration_email': True,
    }
    assert len(mail.outbox) == 0
    resp = app.post_json('/api/users/', params=payload, status=201)
    user_id = resp.json['id']
    assert len(mail.outbox) == 1
    # Follow activation link
    assert re.findall('http://[^ ]*/', mail.outbox[0].body)
    url = re.findall('http://[^ ]*/', mail.outbox[0].body)[0]
    relative_url = url.split('testserver')[1]
    resp = app.get(relative_url, status=200)
    resp.form.set('new_password1', '1234==aA')
    resp.form.set('new_password2', '1234==aA')
    resp = resp.form.submit().follow()
    # Check user was properly logged in
    assert str(app.session['_auth_user_id']) == str(user_id)


def test_api_users_create_force_password_reset(app, client, settings, superuser):
    app.authorization = ('Basic', (superuser.username, superuser.username))
    payload = {
        'username': 'john.doe',
        'first_name': 'John',
        'last_name': 'Doe',
        'email': 'john.doe@example.net',
        'password': '1234',
        'force_password_reset': True,
    }
    app.post_json('/api/users/', params=payload, status=201)
    # Verify password reset is enforced on next login
    resp = login(app, 'john.doe', path='/', password='1234').follow()
    resp.form.set('old_password', '1234')
    resp.form.set('new_password1', '1234==aB')
    resp.form.set('new_password2', '1234==aB')
    resp = resp.form.submit('Submit').follow()
    assert 'Password changed' in resp


def test_api_role_add_member(app, api_user, role, member):
    app.authorization = ('Basic', (api_user.username, api_user.username))
    payload = {
        'role_uuid': role.uuid,
        'role_member': member.uuid
    }

    authorized = api_user.has_perm('a2_rbac.change_role', role)

    if member.username == 'fake' or role.name == 'fake':
        status = 404
    elif authorized:
        status = 201
    else:
        status = 403

    resp = app.post_json('/api/roles/{0}/members/{1}/'.format(role.uuid, member.uuid),
                         params=payload, status=status)
    if status == 404:
        pass
    elif authorized:
        assert resp.json['result'] == 1
        assert resp.json['detail'] == 'User successfully added to role'
    else:
        assert resp.json['result'] == 0
        assert resp.json['errors'] == 'User not allowed to change role'


def test_api_role_remove_member(app, api_user, role, member):
    app.authorization = ('Basic', (api_user.username, api_user.username))

    authorized = api_user.is_superuser or api_user.has_perm('a2_rbac.admin_role', role)

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
        assert resp.json['result'] == 1
        assert resp.json['detail'] == 'User successfully removed from role'
    else:
        assert resp.json['result'] == 0
        assert resp.json['errors'] == 'User not allowed to change role'


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
    response = app.post_json(reverse('a2-api-register'), params=payload, headers=headers,
                             status=400)
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
    response = app.post_json(reverse('a2-api-register'), params=payload, headers=headers)
    assert len(mail.outbox) == 0
    assert response.status_code == 201
    assert response.json['result'] == 1
    assert response.json['user']['username'] == username
    assert response.json['user']['email'] == email
    assert response.json['user']['first_name'] == first_name
    assert response.json['user']['last_name'] == last_name
    assert check_password(password, response.json['user']['password'])
    assert response.json['token']
    assert response.json['validation_url'].startswith('http://testserver/accounts/activate/')
    assert User.objects.count() == 2
    user = User.objects.latest('id')
    assert user.ou == get_default_ou()
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
    response = app.post_json(reverse('a2-api-register'), params=payload, headers=headers,
                             status=400)
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
    response = app.post_json(reverse('a2-api-register'), params=payload, headers=headers)
    assert len(mail.outbox) == 0
    assert response.status_code == 201
    assert response.json['result'] == 1
    assert response.json['user']['username'] == username
    assert response.json['user']['email'] == email
    assert response.json['user']['first_name'] == first_name
    assert response.json['user']['last_name'] == last_name
    assert check_password(password, response.json['user']['password'])
    assert response.json['token']
    assert response.json['validation_url'].startswith('http://testserver/accounts/activate/')
    assert User.objects.count() == 2
    user = User.objects.latest('id')
    assert user.username == username
    assert user.email == email
    assert user.first_name == first_name
    assert user.last_name == last_name
    assert user.check_password(password)


def test_user_synchronization(app, simple_user):
    User = get_user_model()
    Role = get_role_model()

    headers = basic_authorization_header(simple_user)
    uuids = []
    for i in range(100):
        user = User.objects.create(first_name='ben', last_name='dauve')
        uuids.append(user.uuid)
    unknown_uuids = [uuid.uuid4().hex for i in range(100)]
    url = reverse('a2-api-users-synchronization')
    content = {
        'known_uuids': uuids + unknown_uuids,
    }
    random.shuffle(content['known_uuids'])
    response = app.post_json(url, params=content, headers=headers, status=403)

    # give custom_user.search_user permission to user
    r = Role.objects.get_admin_role(ContentType.objects.get_for_model(User),
                                    name='role',
                                    slug='role',
                                    operation=SEARCH_OP)

    r.members.add(simple_user)
    response = app.post_json(url, params=content, headers=headers)
    assert response.json['result'] == 1
    assert set(response.json['unknown_uuids']) == set(unknown_uuids)


def test_api_drf_authentication_class(app, admin, user_ou1, oidc_client):
    url = '/api/users/%s/' % user_ou1.uuid
    # test invalid client
    app.authorization = ('Basic', ('foo', 'bar'))
    resp = app.get(url, status=401)
    assert resp.json['result'] == 0
    assert resp.json['errors'] == "Invalid username/password."
    # test inactive client
    admin.is_active = False
    admin.save()
    app.authorization = ('Basic', (admin.username, admin.username))
    resp = app.get(url, status=401)
    assert resp.json['result'] == 0
    assert resp.json['errors'] == "User inactive or deleted."
    # test oidc client
    app.authorization = ('Basic', (oidc_client.username, oidc_client.username))
    app.get(url, status=200)
    # test oidc client without has API access
    oidc_client.oidc_client.has_api_access = False
    oidc_client.oidc_client.save()
    app.authorization = ('Basic', (oidc_client.username, oidc_client.username))
    response = app.get(url, status=401)
    assert response.json['result'] == 0
    assert response.json['errors']


def test_api_check_password(app, superuser, oidc_client, user_ou1):
    app.authorization = ('Basic', (superuser.username, superuser.username))
    # test with invalid paylaod
    payload = {'username': 'whatever'}
    resp = app.post_json(reverse('a2-api-check-password'), params=payload, status=400)
    assert resp.json['result'] == 0
    assert resp.json['errors'] == {u'password': [u'This field is required.']}
    # test with invalid credentials
    payload = {'username': 'whatever', 'password': 'password'}
    resp = app.post_json(reverse('a2-api-check-password'), params=payload, status=200)
    assert resp.json['result'] == 0
    assert resp.json['errors'] == ["Invalid username/password."]
    # test with valid credentials
    payload = {'username': user_ou1.username, 'password': user_ou1.username}
    resp = app.post_json(reverse('a2-api-check-password'), params=payload, status=200)
    assert resp.json['result'] == 1
    # test valid oidc credentials
    payload = {
        'username': oidc_client.oidc_client.client_id,
        'password': oidc_client.oidc_client.client_secret,
    }
    resp = app.post_json(reverse('a2-api-check-password'), params=payload, status=200)
    assert resp.json['result'] == 1
    assert resp.json['oidc_client'] is True


def test_password_change(app, ou1, admin):
    app.authorization = ('Basic', (admin.username, admin.username))

    User = get_user_model()
    user1 = User(username='john.doe', email='john.doe@example.com', ou=ou1)
    user1.set_password('password')
    user1.save()
    user2 = User(username='john.doe2', email='john.doe@example.com', ou=ou1)
    user2.set_password('password')
    user2.save()

    payload = {
        'email': 'none@example.com',
        'ou': ou1.slug,
        'old_password': 'password',
        'new_password': 'password2',
    }
    url = reverse('a2-api-password-change')
    response = app.post_json(url, params=payload, status=400)
    assert 'errors' in response.json
    assert response.json['result'] == 0

    payload = {
        'email': 'john.doe@example.com',
        'ou': ou1.slug,
        'old_password': 'password',
        'new_password': 'password2',
    }
    response = app.post_json(url, params=payload, status=400)
    assert 'errors' in response.json
    assert response.json['result'] == 0
    user2.delete()

    response = app.post_json(url, params=payload)
    assert response.json['result'] == 1
    assert User.objects.get(username='john.doe').check_password('password2')


def test_password_reset(app, ou1, admin, user_ou1, mailoutbox):
    email = user_ou1.email
    url = reverse('a2-api-users-password-reset', kwargs={'uuid': user_ou1.uuid})
    app.authorization = ('Basic', (user_ou1.username, user_ou1.username))
    app.post(url, status=403)
    app.authorization = ('Basic', (admin.username, admin.username))
    app.get(url, status=405)
    user_ou1.email = ''
    user_ou1.save()
    resp = app.post(url, status=500)
    assert resp.json['result'] == 0
    assert resp.json['reason'] == 'User has no mail'
    user_ou1.email = email
    user_ou1.save()
    app.post(url, status=204)
    assert len(mailoutbox) == 1
    mail = mailoutbox[0]
    assert mail.to[0] == email
    assert 'http://testserver/accounts/password/reset/confirm/' in mail.body


def test_users_email(app, ou1, admin, user_ou1, mailoutbox):
    url = reverse('a2-api-users-email', kwargs={'uuid': user_ou1.uuid})
    # test access error
    app.authorization = ('Basic', (user_ou1.username, user_ou1.username))
    app.post(url, status=403)

    # test method error
    app.authorization = ('Basic', (admin.username, admin.username))
    app.get(url, status=405)

    new_email = 'newmail@yopmail.com'
    resp = app.post_json(url, params={'email': new_email})
    assert resp.json['result'] == 1

    assert len(mailoutbox) == 1
    mail = mailoutbox[0]
    print mail.to
    print mail.body

    assert mail.to[0] == new_email
    assert 'http://testserver/accounts/change-email/verify/' in mail.body
