import pytest

from django.contrib.auth import get_user_model

from utils import login


def test_login_inactive_user(db, app):
    User = get_user_model()
    user1 = User.objects.create(username='john.doe')
    user1.set_password('john.doe')
    user1.save()
    user2 = User.objects.create(username='john.doe')
    user2.set_password('john.doe')
    user2.save()

    login(app, user1)
    assert int(app.session['_auth_user_id']) in [user1.id, user2.id]
    app.get('/logout/').form.submit()
    assert '_auth_user_id' not in app.session
    user1.is_active = False
    user1.save()
    login(app, user1)
    assert int(app.session['_auth_user_id']) == user2.id
    app.get('/logout/').form.submit()
    assert '_auth_user_id' not in app.session
    user2.is_active = False
    user2.save()
    with pytest.raises(AssertionError):
        login(app, user1)
    assert '_auth_user_id' not in app.session


def test_registration_url_on_login_page(db, app):
    response = app.get('/login/?next=/whatever')
    assert 'register/?next=/whatever"' in response
