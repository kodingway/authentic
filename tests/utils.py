from django.core.urlresolvers import reverse

def login(app, user, path=None):
    if path:
        login_page = app.get(path, status=302).follow()
    else:
        login_page = app.get(reverse('auth_login'))
    assert login_page.request.path == reverse('auth_login')
    form = login_page.form
    form.set('username', user.username)
    # password is supposed to be the same as username
    form.set('password', user.username)
    response = form.submit(name='login-password-submit').follow()
    if path:
        assert response.request.path == path
    else:
        assert response.request.path == reverse('auth_homepage')
    assert user.get_full_name() in response
    return response
