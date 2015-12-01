import pytest

pytestmark = pytest.mark.django_db


def test_api_user(logged_app):
    resp = logged_app.get('/api/user/')
    assert isinstance(resp.json, dict)
    assert 'username' in resp.json
    assert 'username' in resp.json

def test_api_users_list(app, user):
    app.authorization = ('Basic', (user.username, user.username))
    resp = app.get('/api/users/')
    assert isinstance(resp.json, dict)
    assert set(['count', 'previous', 'next', 'results']) == set(resp.json.keys())
    assert resp.json['previous'] is None
    assert resp.json['next'] is None
    if user.is_superuser:
        count = 6
    elif user.roles.exists():
        count = 2
    else:
        count = 0
    assert resp.json['count'] == count
    assert len(resp.json['results']) == count

def test_api_users_create(app, user):
    from django.contrib.auth import get_user_model

    app.authorization = ('Basic', (user.username, user.username))
    payload = {
        'ou': None,
        'username': 'john.doe',
        'first_name': 'John',
        'last_name': 'Doe',
        'email': 'john.doe@example.net',
        'password': 'password',
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
                   'date_joined', 'last_login', 'username', 'password', 'email', 'is_active']) == set(resp.json.keys())
        assert resp.json['first_name'] == payload['first_name']
        assert resp.json['last_name'] == payload['last_name']
        assert resp.json['email'] == payload['email']
        assert resp.json['username'] == payload['username']
        assert resp.json['uuid']
        assert resp.json['id']
        assert resp.json['date_joined']
        assert resp.json['last_login']
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
        resp2 = app.get('/api/users/%s/' % resp.json['id'])
        assert resp.json == resp2.json

def test_api_role_add_member(app, user, role, member):
    app.authorization = ('Basic', (user.username, user.username))
    payload = {
        'role_uuid': role.uuid,
        'role_member': member.uuid
    }

    authorized = user.has_perm('a2_rbac.change_role', role)

    if member.username == 'fake' or role.name == 'fake':
        status = 404
    elif authorized :
        status = 201
    else:
        status = 403

    resp = app.post_json('/api/roles/{0}/members/{1}/'.format(role.uuid, member.uuid), payload, status=status)
    if status == 404:
        pass
    elif authorized :
        assert resp.json['detail'] == 'User successfully added to role'
    else:
        assert resp.json['detail'] == 'User not allowed to change role'

def test_api_role_remove_member(app, user, role, member):
    app.authorization = ('Basic', (user.username, user.username))

    authorized = user.is_superuser or user.has_perm('a2_rbac.change_role', role)
    
    if member.username == 'fake' or role.name == 'fake':
        status = 404
    elif authorized :
        status = 200
    else:
        status = 403

    resp = app.delete_json('/api/roles/{0}/members/{1}/'.format(role.uuid, member.uuid), status=status)
  
    if status == 404:
        pass
    elif authorized :
        assert resp.json['detail'] == 'User successfully removed from role'
    else:
        assert resp.json['detail'] == 'User not allowed to change role'
