import json
import pprint
from optparse import make_option


from django.core.management.base import BaseCommand, CommandError
from django.core.exceptions import ValidationError

from authentic2.compat import atomic

from authentic2_auth_oidc.utils import register_issuer
from authentic2_auth_oidc.models import OIDCClaimMapping, OIDCProvider
from django_rbac.utils import get_ou_model


class Command(BaseCommand):
    '''Load LDAP ldif file'''
    can_import_django_settings = True
    requires_model_validation = True
    option_list = BaseCommand.option_list + (
        make_option('--issuer', help='do automatic registration of the issuer'),
        make_option('--openid-configuration', help='file containing the OpenID Connect '
                    'configuration of the OP'),
        make_option('--claim-mapping', default=[], action='append',
                    help='mapping from claim to attribute'),
        make_option('--delete-claim', default=[], action='append',
                    help='delete mapping from claim to attribute'),
        make_option('--client-id', help='registered client ID'),
        make_option('--client-secret', help='register client secret'),
        make_option('--scope', default=[], action='append',
                    help='extra scopes, openid is automatic'),
        make_option('--no-verify', default=False, action='store_true',
                    help='do not verify TLS certificates'),
        make_option('--show', default=False, action='store_true',
                    help='show provider configuration'),
        make_option('--ou-slug', help='slug of the ou, if absent default ou is used'),
    )
    args = '<name>'
    help = 'Register an OpenID Connect OP'

    @atomic
    def handle(self, name, *args, **options):
        openid_configuration = options.get('openid_configuration')
        issuer = options.get('issuer')
        if openid_configuration:
            openid_configuration = json.load(open(openid_configuration))
        if issuer or openid_configuration:
            try:
                ou = None
                if options.get('ou_slug'):
                    OU = get_ou_model()
                    ou = OU.objects.get(slug=options['ou_slug'])
                provider = register_issuer(name, issuer=issuer,
                                           openid_configuration=openid_configuration,
                                           verify=not options['no_verify'],
                                           ou=ou)
            except ValueError as e:
                raise CommandError(e)
        else:
            try:
                provider = OIDCProvider.objects.get(name=name)
            except OIDCProvider.DoesNotExist:
                raise CommandError('Unknown OIDC provider')
        try:
            provider.full_clean()
        except ValidationError as e:
            provider.delete()
            raise CommandError(e)
        client_id = options.get('client_id')
        if client_id:
            provider.client_id = client_id
        client_secret = options.get('client_secret')
        if client_secret:
            provider.client_secret = client_secret
        scope = options.get('scope')
        if scope is not None:
            provider.scopes = ' '.join(filter(None, options['scope']))
        provider.save()

        for claim_mapping in options.get('claim_mapping', []):
            tup = claim_mapping.split()
            if len(tup) < 2:
                raise CommandError('invalid claim mapping %r. it must contain at least a claim and '
                                   'an attribute name')
            claim, attribute = tup[:2]
            claim_options = map(str.strip, tup[2:])
            extra = {
                'verified': 'verified' in claim_options,
                'required': 'required' in claim_options,
                'idtoken_claim': 'idtoken' in claim_options,
            }
            o, created = OIDCClaimMapping.objects.get_or_create(
                provider=provider,
                claim=claim,
                attribute=attribute,
                defaults=extra)
            if not created:
                OIDCClaimMapping.objects.filter(pk=o.pk).update(**extra)
        delete_claims = options.get('delete_claim', [])
        if delete_claims:
            OIDCClaimMapping.objects.filter(provider=provider, claim__in=delete_claims)
        if options.get('show'):
            for field in OIDCProvider._meta.fields:
                print unicode(field.verbose_name), ':',
                value = getattr(provider, field.name)
                if isinstance(value, dict):
                    print
                    pprint.pprint(value)
                elif hasattr(provider, str('get_' + field.attname + '_display')):
                    print getattr(provider, 'get_' + field.attname + '_display')(), '(%s)' % value
                else:
                    print value
            print 'Mappings:'
            for claim_mapping in provider.claim_mappings.all():
                print '-', claim_mapping

