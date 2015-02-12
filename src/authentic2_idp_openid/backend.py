import logging

from django.core.urlresolvers import reverse

from authentic2.utils import Service

from . import models, app_settings


logger = logging.getLogger(__name__)


class OpenIDBackend(object):
    def service_list(self, request):
        if not request.user.is_authenticated():
            return ()
        q = models.TrustedRoot.objects.filter(user=request.user.id)
        ls = []
        for service_provider in q:
            actions = []
            actions.append(('go', 'GET', service_provider.trust_root, None))
            if app_settings.OPENID_ACTIONS:
                tpl = app_settings.OPENID_ACTIONS.get(service_provider.trust_root, None)
                if tpl:
                    actions.append(('template', tpl))
            actions.append(('unlink', 'GET', reverse('trustedroot_delete',
                kwargs={'pk': service_provider.id}), None))
            ls.append(Service(url=None, name=service_provider.trust_root,
                actions=actions))
        return ls
