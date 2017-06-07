import django

from authentic2.utils import good_next_url


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
    settings.A2_REDIRECT_WHITELIST = ['https://google.com']
    assert good_next_url(request, 'https://google.com/')
