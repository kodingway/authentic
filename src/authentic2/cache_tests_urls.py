from . import decorators

from django.conf.urls import patterns, url
from django.http import HttpResponse

@decorators.DjangoCache
def cached_function():
    import random
    return random.random()

def cached_view(self):
    return HttpResponse('%s' % cached_function())

urlpatterns = patterns('',
        url(r'^cache/$', cached_view),
)
