from django.conf.urls import patterns, url

urlpatterns = patterns('a2_test_plugin.views',
        url('^test/', 'test'))
