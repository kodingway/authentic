def login(app, user):
    resp = app.get('/login/')
    form = resp.forms[0]
    form['username'] = user.username
    form['password'] = user.username
    resp = form.submit('login-password-submit')
    assert resp.status_int == 302
    return app
