from django.conf.urls import patterns, url
from django.contrib.auth import views as auth_views, REDIRECT_FIELD_NAME
from django.core.urlresolvers import reverse

from authentic2.utils import get_form_class
from . import app_settings, decorators

SET_PASSWORD_FORM_CLASS = get_form_class(
        app_settings.A2_REGISTRATION_SET_PASSWORD_FORM_CLASS)
CHANGE_PASSWORD_FORM_CLASS = get_form_class(
        app_settings.A2_REGISTRATION_CHANGE_PASSWORD_FORM_CLASS)

@decorators.setting_enabled('A2_REGISTRATION_CAN_CHANGE_PASSWORD')
def password_change_view(request, *args, **kwargs):
    post_change_redirect = kwargs.pop('post_change_redirect', None)
    if 'next_url' in request.POST and request.POST['next_url']:
        post_change_redirect = request.POST['next_url']
    elif REDIRECT_FIELD_NAME in request.GET:
        post_change_redirect = request.GET[REDIRECT_FIELD_NAME]
    elif post_change_redirect is None:
        post_change_redirect = reverse('account_management')
    kwargs['post_change_redirect'] = post_change_redirect
    extra_context = kwargs.setdefault('extra_context', {})
    extra_context[REDIRECT_FIELD_NAME] = post_change_redirect
    return auth_views.password_change(request, *args, **kwargs)


urlpatterns = patterns('authentic2.views',
    url(r'^logged-in/$', 'logged_in', name='logged-in'),
    url(r'^edit/$', 'edit_profile', name='profile_edit'),
    url(r'^change-email/$', 'email_change', name='email-change'),
    url(r'^change-email/verify/$', 'email_change_verify',
        name='email-change-verify'),
    url(r'^$', 'profile', name='account_management'),
    url(r'^password/change/$',
        password_change_view,
        {'password_change_form': CHANGE_PASSWORD_FORM_CLASS},
        name='password_change'),
    url(r'^password/change/done/$',
        auth_views.password_change_done,
        name='password_change_done'),
    url(r'^password/reset/confirm/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',
        auth_views.password_reset_confirm,
        {'set_password_form': SET_PASSWORD_FORM_CLASS},
        name='password_reset_confirm'),
    url(r'^password/reset/$',
        auth_views.password_reset,
        name='password_reset'),
    url(r'^password/reset/complete/$',
        auth_views.password_reset_complete,
        name='password_reset_complete'),
    url(r'^password/reset/done/$',
        auth_views.password_reset_done,
        name='password_reset_done'),
    # Legacy 
    url(r'^password/change/$',
        password_change_view,
        {'password_change_form': CHANGE_PASSWORD_FORM_CLASS},
        name='auth_password_change'),
    url(r'^password/change/done/$',
        auth_views.password_change_done,
        name='auth_password_change_done'),
    url(r'^password/reset/confirm/(?P<uidb36>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',
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
