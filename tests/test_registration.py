
def test_registration_email_blacklist(app, settings, db):
    def test_register(email):
        response = app.get('/accounts/register/')
        assert 'email' in response.form.fields
        response.form.set('email', email)
        response = response.form.submit()
        return response.status_code == 302
    settings.A2_REGISTRATION_EMAIL_BLACKLIST = ['a*@example\.com']
    assert not test_register('aaaa@example.com')
    assert test_register('aaaa@example.com.zob')
    assert test_register('baaaa@example.com')
    settings.A2_REGISTRATION_EMAIL_BLACKLIST = ['a*@example\.com', '^ba*@example\.com$']
    assert not test_register('aaaa@example.com')
    assert not test_register('baaaa@example.com')
    assert test_register('bbaaaa@example.com')
