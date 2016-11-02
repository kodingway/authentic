from django.utils.translation import gettext_noop
from django.shortcuts import render

from authentic2.decorators import GlobalCache

from . import app_settings, models, utils


@GlobalCache(timeout=5)
def get_providers():
    return models.OIDCProvider.objects.all()


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
            'providers': get_providers(),
        }
        return render(request, 'authentic2_auth_oidc/login.html', ctx,
                      context_instance=context_instance)

