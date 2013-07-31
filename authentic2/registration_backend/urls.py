from django.utils.importlib import import_module
from django.conf.urls import patterns, url, include
from django.contrib.auth import views as auth_views


from .. import app_settings


def get_form_class(form_class):
    module, form_class = form_class.rsplit('.', 1)
    module = import_module(module)
    return getattr(module, form_class)


SET_PASSWORD_FORM_CLASS = get_form_class(
        app_settings.A2_REGISTRATION_SET_PASSWORD_FORM_CLASS)
CHANGE_PASSWORD_FORM_CLASS = get_form_class(
        app_settings.A2_REGISTRATION_CHANGE_PASSWORD_FORM_CLASS)


if app_settings.A2_REGISTRATION_AUTHORIZED:
    urlpatterns = patterns('authentic2.registration_backend.views',
                           url(r'^activate/complete/$',
                               'activate_complete',
                               name='registration_activation_complete'),
                           # Activation keys get matched by \w+ instead of the more specific
                           # [a-fA-F0-9]{40} because a bad activation key should still get to the view;
                           # that way it can return a sensible "invalid key" message instead of a
                           # confusing 404.
                           url(r'^activate/(?P<activation_key>\w+)/$',
                               'activate',
                               {'backend': 'authentic2.registration_backend.RegistrationBackend'},
                               name='registration_activate'),
                           url(r'^register/$',
                               'register',
                               {'backend': 'authentic2.registration_backend.RegistrationBackend'},
                               name='registration_register'),
                           url(r'^register/complete/$',
                               'register_complete',
                               name='registration_complete'),
                           url(r'^register/closed/$',
                               'register_closed',
                               name='registration_disallowed'),
                           url(r'^delete/', 'delete', name='delete_account'),
                           )
else:
    urlpatterns = patterns('')

urlpatterns += patterns('authentic2.registration_backend.views',
                       url(r'^password/change/$',
                           'password_change',
                           {'password_change_form': CHANGE_PASSWORD_FORM_CLASS},
                           name='auth_password_change'),
                       url(r'^password/reset/confirm/(?P<uidb36>[0-9A-Za-z]+)-(?P<token>.+)/$',
                           'password_reset_confirm',
                           {'set_password_form': SET_PASSWORD_FORM_CLASS},
                           name='auth_password_reset_confirm'),
                       (r'', include('registration.auth_urls')),
                           )

