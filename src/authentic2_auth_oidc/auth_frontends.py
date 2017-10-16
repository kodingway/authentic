from django.utils.translation import gettext_noop
from django.shortcuts import render

from authentic2.decorators import GlobalCache

from . import app_settings, models, utils


@GlobalCache(timeout=5, kwargs=['shown'])
def get_providers(shown=None):
    qs = models.OIDCProvider.objects.all()
    if shown is not None:
        qs = qs.filter(show=shown)
    return qs


class OIDCFrontend(object):
    def enabled(self):
        return app_settings.ENABLE and utils.has_providers()

    def name(self):
        return gettext_noop('OpenIDConnect')

    def id(self):
        return 'oidc'

    def login(self, request, *args, **kwargs):
        context_instance = kwargs.get('context_instance', None)
        ctx = {
            'providers': get_providers(shown=True),
        }
        return render(request, 'authentic2_auth_oidc/login.html', ctx,
                      context_instance=context_instance)
