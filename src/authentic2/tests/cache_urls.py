from django.conf.urls import patterns, url
from django.http import HttpResponse

from authentic2.decorators import SessionCache, DjangoCache


@DjangoCache
def cached_function():
    import random
    return random.random()


def cached_view(self):
    return HttpResponse('%s' % cached_function())


@SessionCache()
def session_cache_function():
    import random
    return random.random()


def session_cache(request):
    value = session_cache_function()
    return HttpResponse('%s' % value)

urlpatterns = patterns('',
    url(r'^django_cache/$', cached_view),
    url(r'^session_cache/$', session_cache),
)
