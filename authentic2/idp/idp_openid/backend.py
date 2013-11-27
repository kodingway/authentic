import logging

from django.core.urlresolvers import reverse
from django.conf import settings
from authentic2.idp.utils import Service

import models

logger = logging.getLogger('authentic2.idp.idp_openid.backend')


class OpenIDBackend(object):
    def service_list(self, request):
        if not request.user.is_authenticated():
            return ()
        q = models.TrustedRoot.objects.filter(user=request.user.id)
        ls = []
        for service_provider in q:
            actions = []
            actions.append(('go', 'GET', service_provider.trust_root, None))
            if getattr(settings, 'OPENID_ACTIONS', None):
                tpl = settings.OPENID_ACTIONS.get(service_provider.trust_root, None)
                if tpl:
                    actions.append(('template', tpl))
            actions.append(('unlink', 'GET', reverse('trustedroot_delete',
                kwargs={'pk': service_provider.id}), None))
            ls.append(Service(url=None, name=service_provider.trust_root,
                actions=actions))
        return ls
