from django.conf.urls import patterns
from django.conf.urls import url
from django.utils.importlib import import_module
from django.contrib.auth import views as auth_views, REDIRECT_FIELD_NAME
from django.views.generic.base import TemplateView
from django.core.urlresolvers import reverse


from .. import app_settings

from registration.backends.default.views import ActivationView
from .. import decorators

def get_form_class(form_class):
    module, form_class = form_class.rsplit('.', 1)
    module = import_module(module)
    return getattr(module, form_class)


SET_PASSWORD_FORM_CLASS = get_form_class(
        app_settings.A2_REGISTRATION_SET_PASSWORD_FORM_CLASS)
CHANGE_PASSWORD_FORM_CLASS = get_form_class(
        app_settings.A2_REGISTRATION_CHANGE_PASSWORD_FORM_CLASS)

@decorators.setting_enabled('A2_REGISTRATION_CAN_CHANGE_PASSWORD')
def password_change_view(request, *args, **kwargs):
    post_change_redirect = kwargs.pop('post_change_redirect', None)
    if 'next_url' in request.POST:
        post_change_redirect = request.POST['next_url']
    elif REDIRECT_FIELD_NAME in request.GET:
        post_change_redirect = request.GET[REDIRECT_FIELD_NAME]
    elif post_change_redirect is None:
        post_change_redirect = reverse('account_management')
    kwargs['post_change_redirect'] = post_change_redirect
    extra_context = kwargs.setdefault('extra_context', {})
    extra_context[REDIRECT_FIELD_NAME] = post_change_redirect
    return auth_views.password_change(request, *args, **kwargs)


urlpatterns = patterns('authentic2.registration_backend.views',
                       url(r'^activate/complete/$',
                           TemplateView.as_view(template_name='registration/activation_complete.html'),
                           name='registration_activation_complete'),
                       # Activation keys get matched by \w+ instead of the more specific
                       # [a-fA-F0-9]{40} because a bad activation key should still get to the view;
                       # that way it can return a sensible "invalid key" message instead of a
                       # confusing 404.
                       url(r'^activate/(?P<activation_key>\w+)/$',
                           ActivationView.as_view(),
                           name='registration_activate'),
                       url(r'^register/$',
                           'register',
                           name='registration_register'),
                       url(r'^register/complete/$',
                           TemplateView.as_view(template_name='registration/registration_complete.html'),
                           name='registration_complete'),
                       url(r'^register/closed/$',
                           TemplateView.as_view(template_name='registration/registration_closed.html'),
                           name='registration_disallowed'),
                       url(r'^password/change/$', password_change_view,
                           {'password_change_form': CHANGE_PASSWORD_FORM_CLASS},
                           name='auth_password_change'),
                       url(r'^password/change/done/$',
                           auth_views.password_change_done,
                           name='auth_password_change_done'),
                       url(r'^password/reset/$',
                           auth_views.password_reset,
                           name='auth_password_reset'),
                       url(r'^password/reset/confirm/(?P<uidb36>[0-9A-Za-z]+)-(?P<token>.+)/$',
                           auth_views.password_reset_confirm,
                           {'set_password_form': SET_PASSWORD_FORM_CLASS},
                           name='auth_password_reset_confirm'),
                       url(r'^password/reset/complete/$',
                           auth_views.password_reset_complete,
                           name='auth_password_reset_complete'),
                       url(r'^password/reset/done/$',
                           auth_views.password_reset_done,
                           name='auth_password_reset_done'),
                       url(r'^delete/$',
                           'delete',
                           name='delete_account'),
                       )
