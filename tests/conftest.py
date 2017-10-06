# -*- coding: utf-8 -*-

import pytest
import mock

import django_webtest

from django.core.wsgi import get_wsgi_application
from django.contrib.auth import get_user_model
from django_rbac.utils import get_ou_model, get_role_model
from django.conf import settings

from django.contrib.contenttypes.models import ContentType
from pytest_django.migrations import DisableMigrations

from authentic2.a2_rbac.utils import get_default_ou
from authentic2_idp_oidc.models import OIDCClient
from authentic2.authentication import OIDCUser

import utils

Role = get_role_model()

@pytest.fixture
def app(request):
    wtm = django_webtest.WebTestMixin()
    wtm._patch_settings()
    request.addfinalizer(wtm._unpatch_settings)
    return django_webtest.DjangoTestApp(extra_environ={'HTTP_HOST': 'localhost'})


@pytest.fixture
def ou1(db):
    OU = get_ou_model()
    return OU.objects.create(name='OU1', slug='ou1')


@pytest.fixture
def ou2(db):
    OU = get_ou_model()
    return OU.objects.create(name='OU2', slug='ou2')

@pytest.fixture
def ou_rando(db):
    OU = get_ou_model()
    return OU.objects.create(name='ou_rando', slug='ou_rando')

def create_user(**kwargs):
    User = get_user_model()
    password = kwargs.pop('password', None) or kwargs['username']
    user, created = User.objects.get_or_create(**kwargs)
    if password:
        user.set_password(password)
        user.save()
    return user


@pytest.fixture
def simple_user(db, ou1):
    return create_user(username='user', first_name=u'Jôhn', last_name=u'Dôe',
                       email='user@example.net', ou=get_default_ou())


@pytest.fixture
def superuser(db):
    return create_user(username='superuser', first_name='super', last_name='user',
                       email='superuser@example.net', is_superuser=True, is_staff=True,
                       is_active=True, ou=get_default_ou())


@pytest.fixture
def admin(db):
    user = create_user(username='admin', first_name='global', last_name='admin',
                       email='admin@example.net', is_active=True)
    Role = get_role_model()
    user.roles.add(Role.objects.get(slug='_a2-manager'))
    return user


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
def admin_rando_role(db, role_random, ou_rando):
    user = create_user(username='admin_rando', first_name='admin', last_name='rando',
           email='admin.rando@weird.com', ou=ou_rando)
    user.roles.add(ou_rando.get_admin_role())
    return user

@pytest.fixture(params=['superuser', 'user_ou1', 'user_ou2', 'admin_ou1', 'admin_ou2', 'admin_rando_role', 'member_rando'])
def user(request, superuser, user_ou1, user_ou2, admin_ou1, admin_ou2, admin_rando_role, member_rando):
    return locals().get(request.param)

@pytest.fixture
def logged_app(app, user):
    utils.login(app, user)
    return app

@pytest.fixture
def role_random(db, ou_rando):
    return Role.objects.create(name='rando', slug='rando',  ou=ou_rando)

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
def member_rando(db, ou_rando):
    return create_user(username='test', first_name='test', last_name='test',
            email='test@test.org', ou=ou_rando)

@pytest.fixture
def member_fake():
    return type('user', (object,), {'username':'fake', 'uuid': 'fake_uuid'})

@pytest.fixture(params=['member_rando','member_fake'])
def member(request, member_rando, member_fake):
    return locals().get(request.param)

@pytest.fixture(params=['superuser','admin'])
def superuser_or_admin(request, superuser, admin):
    return locals().get(request.param)


@pytest.fixture
def concurrency(settings):
    '''Select a level of concurrency based on the db, sqlite3 is less robust
       thant postgres due to its transaction lock timeout of 5 seconds.
    '''
    if 'sqlite' in settings.DATABASES['default']['ENGINE']:
        return 20
    else:
        return 100


@pytest.fixture
def migrations():
    if isinstance(settings.MIGRATION_MODULES, DisableMigrations):
        pytest.skip('this test requires native migrations')


@pytest.fixture
def oidc_client(db, ou1):
    client = OIDCClient.objects.create(
        name='example', slug='example', client_id='example',
        client_secret='example', authorization_flow=1,
        post_logout_redirect_uris='https://example.net/redirect/',
        identifier_policy=OIDCClient.POLICY_UUID,
        has_api_access=True,
    )

    class TestOIDCUser(OIDCUser):

        def __init__(self, oidc_client):
            super(TestOIDCUser, self).__init__(oidc_client)

        @property
        def username(self):
            return self.oidc_client.client_id

        @property
        def is_superuser(self):
            return False

        @property
        def roles(self):
            return mock.Mock(exists=lambda: True)

        @property
        def ou(self):
            return ou1

    return TestOIDCUser(client)


@pytest.fixture(params=['oidc_client', 'superuser', 'user_ou1', 'user_ou2',
                        'admin_ou1', 'admin_ou2', 'admin_rando_role', 'member_rando'])
def api_user(request, oidc_client, superuser, user_ou1, user_ou2,
         admin_ou1, admin_ou2, admin_rando_role, member_rando):
    return locals().get(request.param)
