import logging
import urllib
import operator
import random

from django.utils.translation import ugettext as _
from django.core.urlresolvers import reverse
from django.template.loader import render_to_string
from django.db.models import Q

import authentic2.saml.models as models
import authentic2.idp.saml.saml2_endpoints as saml2_endpoints
import authentic2.saml.common as common

from authentic2.decorators import to_list
from authentic2.utils import Service


class SamlBackend(object):
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def service_list(self, request):
        q = models.LibertyServiceProvider.objects.all()
        q = q.filter(
            Q(liberty_provider__authorized_roles__isnull=True)
            | Q(liberty_provider__authorized_roles__in=request.user.roles_and_parents()))
        ls = []
        sessions = models.LibertySession.objects.filter(
            django_session_key=request.session.session_key)
        sessions_eids = set(session.provider_id for session in sessions)
        all_policy = common.get_sp_options_policy_all()
        default_policy = common.get_sp_options_policy_default()
        queries = []
        if all_policy and all_policy.idp_initiated_sso:
            queries.append(q)
            queries.append(q.filter(liberty_provider__entity_id__in=sessions_eids))
        else:
            queries.append(q.filter(
                sp_options_policy__enabled=True,
                sp_options_policy__idp_initiated_sso=True))
            queries.append(
                q.filter(
                    sp_options_policy__enabled=True,
                    sp_options_policy__accept_slo=True,
                    liberty_provider__entity_id__in=sessions_eids))
            if default_policy and default_policy.idp_initiated_sso:
                queries.append(
                    q.filter(
                        sp_options_policy__isnull=True))
            if default_policy and default_policy.accept_slo:
                queries.append(
                    q.filter(
                        sp_options_policy__isnull=True,
                        liberty_provider__entity_id__in=sessions_eids))
        qs = reduce(operator.__or__, queries)
        # do some prefetching
        qs = qs.prefetch_related('liberty_provider')
        qs = qs.select_related('sp_options_policy')
        for service_provider in qs:
            liberty_provider = service_provider.liberty_provider
            if all_policy:
                policy = all_policy
            elif (service_provider.enable_following_sp_options_policy
                    and service_provider.sp_options_policy):
                policy = service_provider.sp_options_policy
            else:
                policy = default_policy
            if policy:
                actions = []
                entity_id = liberty_provider.entity_id
                protocol = 'saml2'
                if policy.idp_initiated_sso:
                    actions.append(
                        (
                            'login', 'POST',
                            '/idp/%s/idp_sso/' % protocol,
                            (
                                ('provider_id', entity_id),
                            )
                        )
                    )
                if policy.accept_slo and entity_id in sessions_eids:
                    actions.append(
                        (
                            'logout', 'POST',
                            '/idp/%s/idp_slo/' % protocol,
                            (
                                ('provider_id', entity_id),
                            )
                        )
                    )
                if actions:
                    ls.append(
                        Service(url=None, name=liberty_provider.name, actions=actions))
        return ls

    def logout_list(self, request):
        all_sessions = models.LibertySession.objects.filter(
            django_session_key=request.session.session_key)
        self.logger.debug("all_sessions %r" % all_sessions)
        provider_ids = set([s.provider_id for s in all_sessions])
        self.logger.debug("provider_ids %r" % provider_ids)
        result = []
        for provider_id in provider_ids:
            name = provider_id
            provider = None
            try:
                provider = models.LibertyProvider.objects.get(entity_id=provider_id)
                name = provider.name
            except models.LibertyProvider.DoesNotExist:
                self.logger.error(u'session found for unknown provider %s', provider_id)
            else:
                policy = common.get_sp_options_policy(provider)
                if not policy:
                    self.logger.error(u'No policy found for %s', provider_id)
                elif not policy.forward_slo:
                    self.logger.info(u'%s configured to not reveive slo', provider_id)
                else:
                    url = reverse(saml2_endpoints.idp_slo, args=[provider_id])
                    # add a nonce so this link is never cached
                    nonce = hex(random.getrandbits(128))
                    url = '{0}?provider_id={1}&nonce={2}'.format(
                        url, urllib.quote(provider_id), nonce)
                    name = name or provider_id
                    code = render_to_string('idp/saml/logout_fragment.html', {
                        'needs_iframe': policy.needs_iframe_logout,
                        'name': name, 'url': url,
                        'iframe_timeout': policy.iframe_logout_timeout})
                    result.append(code)
        return result

    def links(self, request):
        if not request.user.is_authenticated():
            return ()
        user = request.user
        links = []
        qs = models.LibertyFederation.objects.filter(
            user=user,
            sp__isnull=False)
        qs = qs.select_related('sp')
        for federation in qs:
            links.append(
                (federation.sp.liberty_provider, federation.name_id_content)
            )
        return links

    def can_synchronous_logout(self, django_sessions_keys):
        return True

    @to_list
    def federation_management(self, request):
        qs = models.LibertyFederation.objects
        qs = qs.filter(sp__users_can_manage_federations=True)
        qs = qs.filter(user=request.user)
        federations = qs.select_related()
        next_url = request.get_full_path()
        for federation in federations:
            url = reverse('a2-idp-saml2-federation-delete', kwargs={'pk': federation.pk})
            yield {
                'name': federation.sp.liberty_provider.name,
                'hidden_inputs': {
                    'next': next_url,
                },
                'buttons': (
                    ('delete', _('Delete')),
                ),
                'url': url,
            }
        qs = models.LibertyProvider.objects
        qs = qs.filter(service_provider__users_can_manage_federations=True)
        qs = qs.exclude(service_provider__libertyfederation__in=federations)
        qs = qs.filter(Q(authorized_roles__isnull=True)
                       | Q(authorized_roles__in=request.user.roles_and_parents()))
        qs = qs.select_related()
        for liberty_provider in qs:
            url = reverse('a2-idp-saml2-idp-sso')
            yield {
                'name': liberty_provider.name,
                'hidden_inputs': {
                    'provider_id': liberty_provider.entity_id,
                    'next': next_url,
                },
                'buttons': (
                    ('create', _('Create')),
                ),
                'url': url,
            }
