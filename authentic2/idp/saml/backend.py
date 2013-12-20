import logging
import urllib

from django.conf import settings
from django.core.urlresolvers import reverse
from django.template.loader import render_to_string

import authentic2.saml.models as models
import authentic2.idp.saml.saml2_endpoints as saml2_endpoints
import authentic2.saml.common as common

from authentic2.idp.utils import Service

logger = logging.getLogger('authentic2.idp.saml.backend')

class SamlBackend(object):
    def service_list(self, request):
        q = models.LibertyServiceProvider.objects.filter(enabled = True)
        ls = []
        for service_provider in q:
            liberty_provider = service_provider.liberty_provider
            policy = common.get_sp_options_policy(liberty_provider)
            if policy:
                actions = []
                entity_id = liberty_provider.entity_id
                protocol = 'saml2'
                if policy.idp_initiated_sso:
                    actions.append(('login', 'POST',
                        '/idp/%s/idp_sso/' % protocol,
                        (('provider_id', entity_id ),)))
                if policy.accept_slo and \
                        models.LibertySession.objects.filter(
                            django_session_key=request.session.session_key,
                            provider_id=entity_id).exists():
                    actions.append(('logout', 'POST',
                        '/idp/%s/idp_slo/' % protocol,
                        (( 'provider_id', entity_id ),)))
                if actions:
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
                    url = reverse(saml2_endpoints.idp_slo, args=[provider_id])
                    url = '{0}?provider_id={1}'.format(url,
                            urllib.quote(provider_id))
                    name = name or provider_id
                    iframe_timeout = getattr(settings, 'IDP_SAML_LOGOUT_TIMEOUT', 300)
                    code = render_to_string('idp/saml/logout_fragment.html', {
                        'name': name, 'url': url,
                        'iframe_timeout': iframe_timeout})
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
