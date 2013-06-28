from django.conf.urls import patterns, url, include
from django.views.generic import TemplateView


from registration.views import activate
from registration.views import register


from .. import app_settings


if app_settings.A2_REGISTRATION_AUTHORIZED:
    urlpatterns = patterns('authentic2.registration_backend.views',
                           url(r'^activate/complete/$',
                               TemplateView.as_view(template_name='registration/activation_complete.html'),
                               name='registration_activation_complete'),
                           # Activation keys get matched by \w+ instead of the more specific
                           # [a-fA-F0-9]{40} because a bad activation key should still get to the view;
                           # that way it can return a sensible "invalid key" message instead of a
                           # confusing 404.
                           url(r'^activate/(?P<activation_key>\w+)/$',
                               activate,
                               {'backend': 'authentic2.registration_backend.RegistrationBackend'},
                               name='registration_activate'),
                           url(r'^register/$',
                               register,
                               {'backend': 'authentic2.registration_backend.RegistrationBackend'},
                               name='registration_register'),
                           url(r'^register/complete/$',
                               TemplateView.as_view(template_name='registration/registration_complete.html'),
                               name='registration_complete'),
                           url(r'^register/closed/$',
                               TemplateView.as_view(template_name='registration/registration_closed.html'),
                               name='registration_disallowed'),
                            url(r'^delete/', 'delete', name='delete_account'),
                           (r'', include('registration.auth_urls')),
                           )
else:
    urlpatterns = patterns('',
                           (r'', include('registration.auth_urls')),
                           )

