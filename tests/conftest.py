# -*- coding: utf-8 -*-

import pytest

import django_webtest

from django.core.wsgi import get_wsgi_application
from django.contrib.auth import get_user_model
from django_rbac.utils import get_ou_model, get_role_model

from django.contrib.contenttypes.models import ContentType

from authentic2.a2_rbac.utils import get_default_ou

import utils

Role = get_role_model()

@pytest.fixture
def app(request):
    wtm = django_webtest.WebTestMixin()
    wtm._patch_settings()
    request.addfinalizer(wtm._unpatch_settings)
    return django_webtest.DjangoTestApp()


@pytest.fixture
def ou1(db):
    OU = get_ou_model()
    return OU.objects.create(name='OU1', slug='ou1')


@pytest.fixture
def ou2(db):
    OU = get_ou_model()
    return OU.objects.create(name='OU2', slug='ou2')

def create_user(**kwargs):
    User = get_user_model()
    password = kwargs.pop('password', None) or kwargs['username']
    user, created = User.objects.get_or_create(**kwargs)
    if password:
        user.set_password(password)
        user.save()
    return user


@pytest.fixture
def superuser(db):
    return create_user(username='superuser', first_name='super', last_name='user',
                       email='superuser@example.net', is_superuser=True, is_staff=True,
                       is_active=True, ou=get_default_ou())


@pytest.fixture
def user_ou1(db, ou1):
    return create_user(username='john.doe', first_name=u'Jôhn', last_name=u'Dôe',
                       email='john.doe@example.net', ou=ou1)


@pytest.fixture
def user_ou2(db, ou2):
    return create_user(username='john.doe', first_name=u'Jôhn', last_name=u'Dôe',
                       email='john.doe@example.net', ou=ou2)


@pytest.fixture
def admin_ou1(db, ou1):
    user = create_user(username='admin.ou1', first_name=u'Admin', last_name=u'OU1',
                       email='admin.ou1@example.net', ou=ou1)
    user.roles.add(ou1.get_admin_role())
    return user


@pytest.fixture
def admin_ou2(db, ou2):
    user = create_user(username='admin.ou2', first_name=u'Admin', last_name=u'OU2',
                       email='admin.ou2@example.net', ou=ou2)
    user.roles.add(ou2.get_admin_role())
    return user

@pytest.fixture
def admin_rando_role(db, role_random):
    user = create_user(username='admin_rando', first_name='admin', last_name='rando',
           email='admin.rando@weird.com')
    user.roles.add(role_random.get_admin_role())
    return user

@pytest.fixture(params=['superuser', 'user_ou1', 'user_ou2', 'admin_ou1', 'admin_ou2', 'admin_rando_role'])
def user(request, superuser, user_ou1, user_ou2, admin_ou1, admin_ou2, admin_rando_role):
    return locals().get(request.param)

@pytest.fixture
def logged_app(app, user):
    return utils.login(app, user)

@pytest.fixture
def role_random(db):
    return Role.objects.create(name='rando', slug='rando')

@pytest.fixture
def role_ou1(db, ou1):
    return Role.objects.create(name='role_ou1', slug='role_ou1', ou=ou1)

@pytest.fixture
def role_ou2(db, ou2):
    return Role.objects.create(name='role_ou2', slug='role_ou2', ou=ou2)

@pytest.fixture(params=['role_random', 'role_ou1', 'role_ou2'])
def role(request, role_random, role_ou1, role_ou2):
    return locals().get(request.param)

@pytest.fixture
def member_rando(db):
    return create_user(username='test', first_name='test', last_name='test',
            email='test@test.org')

@pytest.fixture
def member_fake():
    return type('user', (object,), {'username':'fake', 'uuid': 'fake_uuid'})

@pytest.fixture(params=['member_rando','member_fake'])
def member(request, member_rando, member_fake):
    return locals().get(request.param)
