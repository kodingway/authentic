import logging

import models

logger = logging.getLogger('authentic2.idp.idp_openid.backend')

class OpenIDBackend(object):
    def links(self, request):
        if not request.user.is_authenticated():
            return ()
        return models.TrustedRoot.objects.filter(user=request.user.id)
