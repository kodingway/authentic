# -*- coding: utf-8 -*-
import json
import pytest

from authentic2_provisionning_ldap.ldap_utils import Slapd, has_slapd
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from authentic2.a2_rbac.utils import get_default_ou
from django_rbac.utils import get_ou_model, get_role_model
from authentic2.models import Service

pytestmark = pytest.mark.django_db

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

    role3 = Role.objects.create(name='Role3', ou=ou)
    role4 = Role.objects.create(name='Role4', service=service)

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
                role['is_admin'] == False and
                role['is_service'] == False and
                role['ou__uuid'] == ou.uuid and
                role['ou__name'] == ou.name and
                role['ou__slug'] == ou.slug) or \
               (role['uuid'] == role2.uuid and
                role['name'] == role2.name and
                role['slug'] == role2.slug and
                role['is_admin'] == False and
                role['is_service'] == True and
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
                role['is_admin'] == False and
                role['is_service'] == False and
                role['ou__uuid'] == ou.uuid and
                role['ou__name'] == ou.name and
                role['ou__slug'] == ou.slug) or \
               (role['uuid'] == role2.uuid and
                role['name'] == role2.name and
                role['slug'] == role2.slug and
                role['is_admin'] == False and
                role['is_service'] == True and
                role['ou__uuid'] == ou.uuid and
                role['ou__name'] == ou.name and
                role['ou__slug'] == ou.slug)
