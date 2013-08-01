import logging

from django.core.urlresolvers import reverse
from django.utils.translation import ugettext as _

import authentic2.saml.models as models
import authentic2.idp.saml.saml2_endpoints as saml2_endpoints
import authentic2.saml.common as common

logger = logging.getLogger('authentic2.idp.saml.backend')

class Service(object):
    url = None
    name = None
    actions = []

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

class SamlBackend(object):
    def service_list(self, request):
        q = models.LibertyServiceProvider.objects.filter(enabled = True)
        ls = []
        for service_provider in q:
            liberty_provider = service_provider.liberty_provider
            policy = common.get_sp_options_policy(liberty_provider)
            if policy and policy.idp_initiated_sso:
                actions = []
                entity_id = liberty_provider.entity_id
                protocol = 'saml2'
                actions.append(('login', 'POST',
                    '/idp/%s/idp_sso/' % protocol,
                    (('provider_id', entity_id ),)))
                if models.LibertySession.objects.filter(
                        django_session_key=request.session.session_key,
                        provider_id=entity_id).exists():
                    actions.append(('logout', 'POST',
                        '/idp/%s/idp_slo/' % protocol,
                        (( 'provider_id', entity_id ),)))
                ls.append(Service(url=None, name=liberty_provider.name,
                    actions=actions))
        return ls

    def logout_list(self, request):
        all_sessions = models.LibertySession.objects.filter(
                django_session_key=request.session.session_key)
        logger.debug("logout_list: all_sessions %r" % all_sessions)
        provider_ids = set([s.provider_id for s in all_sessions])
        logger.debug("logout_list: provider_ids %r" % provider_ids)
        result = []
        for provider_id in provider_ids:
            name = provider_id
            provider = None
            try:
                provider = models.LibertyProvider.objects.get(entity_id=provider_id)
                name = provider.name
            except models.LibertyProvider.DoesNotExist:
                logger.error('logout_list: session found for unknown provider %s' \
                    % provider_id)
            else:
                policy = common.get_sp_options_policy(provider)
                if not policy:
                    logger.error('logout_list: No policy found for %s' % provider_id)
                elif not policy.forward_slo:
                    logger.info('logout_list: %s configured to not reveive slo' \
                        % provider_id)
                else:
                    code = '<div>'
                    code += _('Sending logout to %(name)s....') % { 'name': name or provider_id}
                    code += '<iframe src="%s?provider_id=%s" marginwidth="0" marginheight="0" \
        scrolling="no" style="border: none" width="16" height="16"></iframe></div>' % \
                            (reverse(saml2_endpoints.idp_slo, args=[provider_id]), provider_id)
                    logger.debug("logout_list: code %r" % code)
                    result.append(code)
        return result

    def links(self, request):
        if not request.user.is_authenticated():
            return ()
        user = request.user
        links = []
        qs = models.LibertyFederation.objects \
                .filter(user=user,
                        sp__isnull=False) \
                .select_related('sp')
        for federation in qs:
            links.append((federation.sp.liberty_provider,
                federation.name_id_content))
        return links

    def can_synchronous_logout(self, django_sessions_keys):
        return True
