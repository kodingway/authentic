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
    assert isinstance(resp.json, list)
    if user.is_superuser:
        assert len(resp.json) == 5
    elif user.roles.exists():
        assert len(resp.json) == 2
    else:
        assert len(resp.json) == 0

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
