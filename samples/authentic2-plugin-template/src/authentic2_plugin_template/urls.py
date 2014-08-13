from django.conf.urls import patterns, url

from .views import index

urlpatterns = patterns('',
        url('^authentic2_plugin_template/$', index,
            name='authentic2-plugin-template-index'),
)
