from optparse import make_option

try:
    import ldap
    from ldap.dn import str2dn, dn2str
    from ldap.filter import filter_format
except ImportError:
    ldap = None

from django.core.management.base import BaseCommand

from authentic2.attributes_ng.engine import get_attributes
from authentic2 import compat, utils

from authentic2_provisionning_ldap import app_settings, ldap_utils

ADD = 1
REPLACE = 2
DELETE = 3



class Command(BaseCommand):
    can_import_django_settings = True
    output_transaction = True
    requires_model_validation = True
    option_list = BaseCommand.option_list + (
        make_option('--fake',
            action='store_true',
            default=False,
            help='Do nothing, just simulate'),
        make_option('--batch-size',
            action='store',
            type='int',
            default=200,
            help='Batch size'),
    )

    def handle(self, *args, **options):
        ressources = app_settings.RESSOURCES
        if args:
            ressources = [ressource for ressource in ressources
                    if ressource.get('name') in args]
        for ressource in ressources:
            self.sync_ressource(ressource, **options)

    def sync_ressource(self, ressource, **options):
        self.sync_ldap_ressource(ressource, **options)

    def add_values(self, ldap_attributes, ldap_attribute, values):
        if not isinstance(values, (list, tuple)):
            values = [values]
        ldap_values = ldap_attributes.setdefault(ldap_attribute, [])
        for value in values:
            if isinstance(value, unicode):
                value = value.encode('utf-8')
            elif isinstance(value, str):
                pass # must be well encoded
            else:
                raise NotImplementedError('value %r not supported' % value)
            ldap_values.append(value)

    def build_dn_and_filter(self, ressource, ldap_attributes):
        '''Build the target record dn'''
        base_dn = ressource['base_dn']
        rdn_attributes = ressource['rdn_attributes']
        dn = str2dn(base_dn)
        rdn = []
        for ldap_attribute in rdn_attributes:
            values = ldap_attributes.get(ldap_attribute, [])
            assert len(values) == 1, 'RDN attribute must have exactly one value %r %r' % \
                (rdn_attributes, ldap_attributes)
            rdn.append((ldap_attribute, values[0], 1))
        dn = [rdn] + dn
        return dn2str(dn), ('&', [(a,b) for a, b, c in rdn])

    def format_filter(self, filters):
        if isinstance(filters, basestring):
            return filters
        assert len(filters) == 2, 'filters %r' % (filters,)
        if isinstance(filters[1], (list, tuple)):
            return '(%s%s)' % (filters[0], ''.join(self.format_filter(x) for x in filters[1]))
        else:
            return filter_format('(%s=%%s)' % filters[0], (filters[1],))

    def sync_ldap_ressource(self, ressource, **options):
        verbosity = int(options['verbosity'])
        fake = options['fake']
        # FIXME: Check ressource well formedness
        conn = ldap_utils.PagedLDAPObject(ressource['url'], retry_max=10,
                retry_delay=2)
        base_dn = ressource['base_dn']
        use_tls = ressource.get('use_tls')
        bind_dn = ressource.get('bind_dn')
        bind_pw = ressource.get('bind_pw')
        if use_tls:
            conn.start_tls_s()
        if bind_dn:
            conn.simple_bind_s(bind_dn, bind_pw)
        attribute_mapping = utils.lower_keys(ressource['attribute_mapping'])
        static_attributes = utils.lower_keys(ressource.get('static_attributes', {}))
        format_mapping = utils.lower_keys(ressource.get('format_mapping', {}))
        attributes = set(attribute_mapping.keys()) | set(static_attributes.keys())
        default_ctx = ressource.get('attribute_context', {})
        ldap_filter = ressource.get('ldap_filter', '(objectclass=*)')
        delete = ressource.get('delete', True)
        User = compat.get_user_model()
        qs = User.objects.filter(**ressource.get('a2_filter', {}))
        todelete = set()
        user_dns = set()
        for batch in utils.batch(qs, options['batch_size']):
            ldap_users = {}
            filters = []
            for user in batch:
                ctx = default_ctx.copy()
                ctx['user'] = user
                ctx = get_attributes(ctx)
                ldap_attributes = {}
                for ldap_attribute, a2_attributes in attribute_mapping.iteritems():
                    if not isinstance(a2_attributes, (tuple, list)):
                        a2_attributes = [a2_attributes]
                    for a2_attribute in a2_attributes:
                        self.add_values(ldap_attributes, ldap_attribute, ctx.get(a2_attribute))
                for ldap_attribute, values in static_attributes.iteritems():
                    self.add_values(ldap_attributes, ldap_attribute, values)
                for ldap_attribute, fmt_tpls in format_mapping.iteritems():
                    for fmt_tpl in fmt_tpls:
                        self.add_values(ldap_attributes, ldap_attribute,
                                [fmt_tpl.format(**ctx)])
                dn, filt = self.build_dn_and_filter(ressource, ldap_attributes)
                user_dns.add(dn)
                ldap_users[dn] = ldap_attributes
                filters.append(filt)
            batch_filter = ldap_filter
            if filters:
                batch_filter = self.format_filter(('&', (batch_filter, ('|',
                    filters))))
            existing_dn = set()
            for dn, entry in conn.paged_search_ext_s(base_dn,
                     ldap.SCOPE_SUBTREE,
                     batch_filter, list(attributes)):
                entry = utils.to_dict_of_set(utils.lower_keys(entry))
                if dn not in ldap_users:
                    todelete.add(dn)
                    continue
                if entry == utils.to_dict_of_set(ldap_users[dn]):
                    # no need to update, entry is already ok
                    del ldap_users[dn]
                    continue
                existing_dn.add(dn)
            for dn, ldap_attributes in ldap_users.iteritems():
                if dn in existing_dn:
                    modlist = []
                    for key, values in ldap_attributes:
                        modlist.append((ldap.MOD_REPLACE, key, values))
                    if not fake:
                        conn.modify(dn, modlist)
                    if verbosity > 1:
                        print '- Replace %s values for %s' % (dn, ', '.join(ldap_attributes.keys()))
                else:
                    if not fake:
                        conn.add(dn, ldap.modlist.addModlist(ldap_attributes))
                    if verbosity > 1:
                        print '- Add %s with values for %s' % (dn, ', '.join(ldap_attributes.keys()))
            # wait for results
            if not fake:
                for x in ldap_users:
                    conn.result()
        for dn, entry in conn.paged_search_ext_s(base_dn,
                ldap.SCOPE_SUBTREE, ldap_filter):
            # ignore the basedn
            if dn == base_dn:
                continue
            if dn not in user_dns and dn not in todelete:
                if not fake:
                    todelete.add(dn)
        if delete:
            if verbosity > 1:
                print '- Deleting:', ', '.join(todelete)
            if not fake:
                for dn in todelete:
                    conn.delete(dn)
                for dn in todelete:
                    conn.result()
