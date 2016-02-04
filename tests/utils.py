from django.core.urlresolvers import reverse

def login(app, user, path=None, password=None):
    if path:
        login_page = app.get(path, status=302).follow()
    else:
        login_page = app.get(reverse('auth_login'))
    assert login_page.request.path == reverse('auth_login')
    form = login_page.form
    form.set('username', user.username if hasattr(user, 'username') else user)
    # password is supposed to be the same as username
    form.set('password', password or user.username)
    response = form.submit(name='login-password-submit').follow()
    if path:
        assert response.request.path == path
    else:
        assert response.request.path == reverse('auth_homepage')
    assert '_auth_user_id' in app.session
    return response
