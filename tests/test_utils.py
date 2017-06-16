import django

from authentic2.utils import good_next_url, same_origin, select_next_url


def test_good_next_url(rf, settings):
    request = rf.get('/', HTTP_HOST='example.net', **{'wsgi.url_scheme': 'https'})
    assert good_next_url(request, '/admin/')
    assert good_next_url(request, '/')
    assert good_next_url(request, 'https://example.net/')
    if django.VERSION >= (1, 8):
        assert good_next_url(request, 'https://example.net:443/')
    assert not good_next_url(request, 'https://example.net:4443/')
    assert not good_next_url(request, 'http://example.net/')
    assert not good_next_url(request, 'https://google.com/')
    assert not good_next_url(request, '')
    assert not good_next_url(request, None)
    settings.A2_REDIRECT_WHITELIST = ['https://google.com', '//.example.com/']
    assert good_next_url(request, 'https://google.com/')
    assert good_next_url(request, 'https://www.example.com/')


def test_same_origin():
    assert same_origin('http://example.com/coin/', 'http://example.com/')
    assert same_origin('http://example.com/coin/', 'http://example.com:80/')
    assert same_origin('http://example.com:80/coin/', 'http://example.com/')
    assert same_origin('http://example.com:80/coin/', 'http://.example.com/')
    assert same_origin('http://example.com:80/coin/', '//example.com/')
    assert not same_origin('https://example.com:80/coin/', 'http://example.com/')
    assert not same_origin('http://example.com/coin/', 'http://bob.example.com/')
    assert same_origin('https://example.com/coin/', 'https://example.com:443/')
    assert not same_origin('https://example.com:34/coin/', 'https://example.com/')
    assert same_origin('https://example.com:34/coin/', '//example.com')
    assert not same_origin('https://example.com/coin/', '//example.com:34')
    assert same_origin('https://example.com:443/coin/', 'https://example.com/')
    assert same_origin('https://example.com:34/coin/', '//example.com')


def test_select_next_url(rf, settings):
    request = rf.get('/accounts/register/', data={'next': '/admin/'})
    assert select_next_url(request, '/') == '/admin/'
    request = rf.get('/accounts/register/', data={'next': 'http://example.com/'})
    assert select_next_url(request, '/') == '/'
    settings.A2_REDIRECT_WHITELIST = ['//example.com/']
    assert select_next_url(request, '/') == 'http://example.com/'
