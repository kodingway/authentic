from django.conf.urls import patterns, url
from django.contrib.auth import views as auth_views

from authentic2.utils import get_form_class
from . import app_settings

SET_PASSWORD_FORM_CLASS = get_form_class(
        app_settings.A2_REGISTRATION_SET_PASSWORD_FORM_CLASS)
CHANGE_PASSWORD_FORM_CLASS = get_form_class(
        app_settings.A2_REGISTRATION_CHANGE_PASSWORD_FORM_CLASS)

urlpatterns = patterns('authentic2.views',
    url(r'^logged-in/$', 'logged_in', name='logged-in'),
    url(r'^edit/$', 'edit_profile', name='profile_edit'),
    url(r'^change-email/$', 'email_change', name='email-change'),
    url(r'^change-email/verify/$', 'email_change_verify',
        name='email-change-verify'),
    url(r'^$', 'profile', name='account_management'),
    url(r'^password/change/$',
        auth_views.password_change,
        {'password_change_form': CHANGE_PASSWORD_FORM_CLASS},
        name='auth_password_change'),
    url(r'^password/change/done/$',
        auth_views.password_change_done,
        name='auth_password_change_done'),
    url(r'^password/reset/confirm/(?P<uidb36>[0-9A-Za-z]+)-(?P<token>.+)/$',
        auth_views.password_reset_confirm,
        {'set_password_form': SET_PASSWORD_FORM_CLASS},
        name='auth_password_reset_confirm'),
    url(r'^password/reset/$',
        auth_views.password_reset,
        name='auth_password_reset'),
    url(r'^password/reset/complete/$',
        auth_views.password_reset_complete,
        name='auth_password_reset_complete'),
    url(r'^password/reset/done/$',
        auth_views.password_reset_done,
        name='auth_password_reset_done'),
)
