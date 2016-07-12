try:
    import ldap
    import ldap.modlist
    import ldap.sasl
    from ldap.filter import filter_format
    from ldap.dn import escape_dn_chars
    from ldap.ldapobject import ReconnectLDAPObject
except ImportError:
    ldap = None
import logging
import random
import base64
import urllib
import six
import os

# code originaly copied from by now merely inspired by
# http://www.amherst.k12.oh.us/django-ldap.html

log = logging.getLogger(__name__)

from django.core.exceptions import ImproperlyConfigured
from django.conf import settings
from django.contrib.auth.models import Group

from authentic2.compat_lasso import lasso

from authentic2 import crypto
from authentic2.decorators import to_list
from authentic2.compat import get_user_model
from authentic2.models import UserExternalId
from authentic2.middleware import StoreRequestMiddleware
from authentic2.user_login_failure import user_login_failure, user_login_success
from django_rbac.utils import get_ou_model
from authentic2.a2_rbac.utils import get_default_ou
from authentic2.ldap_utils import FilterFormatter
from authentic2.utils import utf8_encode

DEFAULT_CA_BUNDLE = ''

CA_BUNDLE_PATHS = [
    '/etc/pki/tls/certs/ca-bundle.crt',  # RHEL/Fedora
    '/etc/ssl/certs/ca-certificates.crt',  # Debian
    '/var/lib/ca-certificates/ca-bundle.pem',  # OpenSuse
]

# Select a system certificate store
for bundle_path in CA_BUNDLE_PATHS:
    if os.path.exists(bundle_path):
        DEFAULT_CA_BUNDLE = bundle_path
        break


class LDAPUser(get_user_model()):
    SESSION_LDAP_DATA_KEY = 'ldap-data'
    _changed = False

    class Meta:
        proxy = True
        app_label = 'authentic2'

    @property
    def block(self):
        return self.ldap_data['block']

    @property
    def dn(self):
        return self.ldap_data['dn']

    def ldap_init(self, block, dn):
        self.ldap_data = {
            'block': block,
            'dn': dn,
        }

    def init_from_session(self, session):
        if self.SESSION_LDAP_DATA_KEY in session:
            self.ldap_data = utf8_encode(session[self.SESSION_LDAP_DATA_KEY])

            # retrieve encrypted bind pw if necessary
            encrypted_bindpw = self.ldap_data.get('block', {}).get('encrypted_bindpw')
            if encrypted_bindpw:
                decrypted = crypto.aes_base64_decrypt(settings.SECRET_KEY, encrypted_bindpw,
                                                      raise_on_error=False)
                if decrypted:
                    self.ldap_data['block']['bindpw'] = decrypted
                    del self.ldap_data['block']['encrypted_bindpw']

    def init_to_session(self, session):
        # encrypt bind password in sessions
        data = dict(self.ldap_data)
        data['block'] = dict(data['block'])
        if data['block'].get('bindpw'):
            data['block']['encrypted_bindpw'] = crypto.aes_base64_encrypt(settings.SECRET_KEY,
                                                                          data['block']['bindpw'])
            del data['block']['bindpw']
        session[self.SESSION_LDAP_DATA_KEY] = data

    def update_request(self):
        request = StoreRequestMiddleware.get_request()
        if request:
            assert not request.session is None
            self.init_to_session(request.session)

    def init_from_request(self):
        request = StoreRequestMiddleware.get_request()
        assert request and not request.session is None
        self.init_from_session(request.session)

    def keep_password(self, password):
        if not password:
            return
        if self.block.get('keep_password_in_session', False):
            self.keep_password_in_session(password)
        if self.block['keep_password']:
            if not super(LDAPUser, self).check_password(password):
                super(LDAPUser, self).set_password(password)
                self._changed = True
        else:
            if super(LDAPUser, self).has_usable_password():
                self.set_unusable_password()
                self._changed = True

    def keep_password_in_session(self, password):
        cache = self.ldap_data.setdefault('password', {})
        if password is not None:
            # Prevent eavesdropping of the password through the session storage
            password = crypto.aes_base64_encrypt(settings.SECRET_KEY, password)
        cache[self.dn] = password
        # ensure session is marked dirty
        self.update_request()

    def get_password_in_session(self):
        if self.block.get('keep_password_in_session', False):
            cache = self.ldap_data.get('passwords', {})
            password = cache.get(self.dn)
            if password is not None:
                try:
                    password = crypto.aes_base64_decrypt(settings.SECRET_KEY, password)
                except crypto.DecryptionError:
                    logging.getLogger(__name__).error('unable to decrypt a stored LDAP password')
                    self.keep_password_in_session(None)
                    password = None
            return password
        else:
            self.keep_password_in_session(None)
            return None

    def check_password(self, raw_password):
        connection = self.ldap_backend.get_connection(self.block)
        try:
            connection.simple_bind_s(self.dn, raw_password.encode('utf-8'))
        except ldap.INVALID_CREDENTIALS:
            return False
        except ldap.LDAPError, e:
            log.error('LDAPUser.check_password() failed: %s', e)
            return False
        self.old_password = raw_password
        return True

    def set_password(self, new_password):
        # Allow change password to work in all cases, as the form does a check_password() first
        # if the verify pass, we have the old password stored in self.old_password
        old_password = getattr(self, 'old_password') or self.get_password_in_session()
        if old_password != new_password:
            conn = self.get_connection()
            self.ldap_backend.modify_password(conn, self.block, self.dn, old_password, new_password)
        self.keep_password_in_session(new_password)
        if self.block['keep_password']:
            super(LDAPUser, self).set_password(new_password)
        else:
            self.set_unusable_password()

    def has_usable_password(self):
        return self.block['user_can_change_password']

    def get_connection(self):
        ldap_password = self.get_password_in_session()
        credentials = ()
        if ldap_password:
            credentials = (self.dn, ldap_password)
        # must be redone if session is older than current code update and new
        # options have been added to the setting dictionnary for LDAP
        # authentication
        self.ldap_backend.update_default(self.block)
        return self.ldap_backend.get_connection(self.block, credentials=credentials)

    def get_attributes(self):
        conn = self.get_connection()
        return self.ldap_backend.get_ldap_attributes(self.block, conn, self.dn)

    def save(self, *args, **kwargs):
        if hasattr(self, 'keep_pk'):
            pk = self.pk
            self.pk = self.keep_pk
        super(LDAPUser, self).save(*args, **kwargs)
        if hasattr(self, 'keep_pk'):
            self.pk = pk


class LDAPBackend(object):
    _DEFAULTS = {
        'binddn': None,
        'bindpw': None,
        'bindsasl': (),
        'user_dn_template': None,
        'user_filter': 'uid=%s',
        'sync_ldap_users_filter': None,
        'user_basedn': None,
        'group_dn_template': None,
        'member_of_attribute': None,
        'group_filter': '(&(member={user_dn})(objectClass=groupOfNames))',
        'group': None,
        'groupsu': None,
        'groupstaff': None,
        'groupactive': None,
        'group_mapping': (),
        'replicas': True,
        'email_field': 'mail',
        'fname_field': 'givenName',
        'lname_field': 'sn',
        'timeout': -1,
        'referrals': False,
        'disable_update': False,
        'use_for_data': None,
        'bind_with_username': False,
        # always use the first URL to build the external id
        'use_first_url_for_external_id': True,
        # active directory ?
        'active_directory': False,
        # shuffle replicas
        'shuffle_replicas': True,
        # all users from this LDAP are superusers
        'is_superuser': None,
        # all users from this LDAP are staff
        'is_staff': None,
        # create missing group if needed
        'create_group': False,
        # attributes to retrieve and store with the user object
        'attributes': ['uid'],
        # default value for some attributes
        'mandatory_attributes_values': {},
        # mapping from LDAP attributes name to other names
        'attribute_mappings': [],
        # realm for selecting an ldap configuration or formatting usernames
        'realm': 'ldap',
        # template for building username
        'username_template': '{uid[0]}@{realm}',
        # allow to match multiple user records
        'multimatch': True,
        # update username on all login, use with CAUTION !! only if you know that
        # generated username are unique
        'update_username': False,
        # lookup existing user with an external id build with attributes
        'lookups': ('external_id', 'username'),
        'external_id_tuples': (('uid',), ('dn:noquote',),),
        # keep password around so that Django authentification also work
        'clean_external_id_on_update': True,
        # Conserve the passsword in the Django User object
        'keep_password': False,
        # Converse the password in the session if needed to retrieve attributes or change password
        'keep_password_in_session': False,
        # Only authenticate users coming from the corresponding realm
        'limit_to_realm': False,
        # Assign users mandatorily to some groups
        'set_mandatory_groups': (),
        # Can users change their password ?
        'user_can_change_password': True,
        # Use starttls
        'use_tls': True,
        # Require certificate
        'require_cert': 'demand',
        # client and server certificates
        'cacertfile': DEFAULT_CA_BUNDLE,
        'cacertdir': '',
        'certfile': '',
        'keyfile': '',
        # LDAP library options
        'ldap_options': {
        },
        'global_ldap_options': {
        },
        # Use Password Modify extended operation
        'use_password_modify': True,
        # Target OU
        'ou_slug': '',
    }
    _REQUIRED = ('url', 'basedn')
    _TO_ITERABLE = ('url', 'groupsu', 'groupstaff', 'groupactive')
    _TO_LOWERCASE = ('fname_field', 'lname_field', 'email_field', 'attributes',
                     'mandatory_attributes_values')
    _VALID_CONFIG_KEYS = list(set(_REQUIRED).union(set(_DEFAULTS)))

    @classmethod
    @to_list
    def get_realms(cls):
        config = cls.get_config()
        for block in config:
            yield block['realm']

    @classmethod
    def get_config(cls):
        if not getattr(settings, 'LDAP_AUTH_SETTINGS', []):
            return []
        if isinstance(settings.LDAP_AUTH_SETTINGS[0], dict):
            blocks = settings.LDAP_AUTH_SETTINGS
        else:
            blocks = (cls._parse_simple_config(),)
        # First get our configuration into a standard format
        for block in blocks:
            cls.update_default(block)
        log.debug('got config %r', blocks)
        return blocks

    def authenticate(self, username=None, password=None, realm=None):
        if username is None or password is None:
            return None

        config = self.get_config()
        if not config:
            return

        if not ldap:
            raise ImproperlyConfigured('ldap is not available')

        # Now we can try to authenticate
        for block in config:
            uid = username
            if block['limit_to_realm']:
                if realm is None and '@' in username:
                    uid, realm = username.rsplit('@', 1)
                if realm and block.get('realm') != realm:
                    continue
            user = self.authenticate_block(block, uid, password)
            if user is not None:
                return user

    def authenticate_block(self, block, username, password):
        utf8_username = username.encode('utf-8')
        utf8_password = password.encode('utf-8')

        for conn in self.get_connections(block):
            authz_ids = []
            user_basedn = block.get('user_basedn') or block['basedn']

            try:
                if block['user_dn_template']:
                    template = str(block['user_dn_template'])
                    escaped_username = escape_dn_chars(utf8_username)
                    authz_ids.append(template.format(username=escaped_username))
                else:
                    try:
                        if block.get('bind_with_username'):
                            authz_ids.append(utf8_username)
                        elif block['user_filter']:
                            # allow multiple occurences of the username in the filter
                            user_filter = block['user_filter']
                            n = len(user_filter.split('%s')) - 1
                            try:
                                query = filter_format(user_filter, (utf8_username,) * n)
                            except TypeError, e:
                                log.error('user_filter syntax error %r: %s', block['user_filter'],
                                          e)
                                return
                            log.debug('looking up dn for username %r using query %r', username,
                                      query)
                            results = conn.search_s(user_basedn, ldap.SCOPE_SUBTREE, query)
                            # remove search references
                            results = [result for result in results if result[0] is not None]
                            log.debug('found dns %r', results)
                            if len(results) == 0:
                                log.debug('user lookup failed: no entry found, %s' % query)
                            elif not block['multimatch'] and len(results) > 1:
                                log.error('user lookup failed: too many (%d) entries found: %s',
                                          len(results), query)
                            else:
                                authz_ids.extend(result[0] for result in results)
                        else:
                            raise NotImplementedError
                    except ldap.NO_SUCH_OBJECT:
                        log.error('user lookup failed: basedn %s not found', user_basedn)
                        if block['replicas']:
                            break
                        continue
                    except ldap.LDAPError, e:
                        log.error('user lookup failed: with query %r got error %s: %s', username,
                                  query, e)
                        continue
                if not authz_ids:
                    continue

                try:
                    for authz_id in authz_ids:
                        try:
                            conn.simple_bind_s(authz_id, utf8_password)
                            user_login_success(authz_id)
                            break
                        except ldap.INVALID_CREDENTIALS:
                            user_login_failure(authz_id)
                            pass
                    else:
                        log.debug('user bind failed: invalid credentials')
                        if block['replicas']:
                            break
                        continue
                except ldap.NO_SUCH_OBJECT:
                    # should not happen as we just searched for this object !
                    log.error('user bind failed: authz_id not found %r', ', '.join(authz_ids))
                    if block['replicas']:
                        break
                return self._return_user(authz_id, password, conn, block)
            except ldap.CONNECT_ERROR:
                log.error('connection to %r failed, did you forget to declare the TLS certificate '
                          'in /etc/ldap/ldap.conf ?', block['url'])
            except ldap.TIMEOUT:
                log.error('connection to %r timed out', block['url'])
            except ldap.SERVER_DOWN:
                log.error('ldap authentication error: %r is down', block['url'])
            finally:
                del conn
        return None

    def get_user(self, user_id, session=None):
        try:
            try:
                user_id = int(user_id)
            except ValueError:
                return None
            user = LDAPUser.objects.get(pk=user_id)
            # retrieve data from current request
            if session:
                user.init_from_session(session)
            else:
                user.init_from_request()
            return user
        except LDAPUser.DoesNotExist:
            return None

    @classmethod
    def _parse_simple_config(self):
        if len(settings.LDAP_AUTH_SETTINGS) < 2:
            raise ImproperlyConfigured('In a minimal configuration, you must at least specify '
                                       'url and user DN')
        return {'url': settings.LDAP_AUTH_SETTINGS[0], 'basedn': settings.LDAP_AUTH_SETTINGS[1]}

    def backend_name(self):
        return '%s.%s' % (__name__, self.__class__.__name__)

    def create_username(self, block, attributes):
        '''Build a username using the configured template'''
        username_template = unicode(block['username_template'])
        return username_template.format(realm=block['realm'],
                                        **attributes)

    def populate_user_attributes(self, user, block, attributes):
        for legacy_attribute, legacy_field in (('email', 'email_field'),
                                               ('first_name', 'fname_field'),
                                               ('last_name', 'lname_field')):
            ldap_attribute = block[legacy_field]
            if not ldap_attribute:
                break
            if ldap_attribute in attributes:
                value = attributes[ldap_attribute][0]
            else:
                value = u''
            if getattr(user, legacy_attribute) != value:
                setattr(user, legacy_attribute, value)
                user._changed = True
        user.attributes = attributes

    def populate_admin_flags_by_group(self, user, block, group_dns):
        '''Attribute admin flags based on groups.

           It supersedes is_staff, is_superuser and is_active.'''
        for g, attr in (('groupsu', 'is_superuser'),
                        ('groupstaff', 'is_staff'),
                        ('groupactive', 'is_active')):
            group_dns_to_match = block[g]
            if not group_dns_to_match:
                continue
            for group_dn in group_dns_to_match:
                if group_dn in group_dns:
                    v = True
                    break
            else:
                v = False
            if getattr(user, attr) != v:
                setattr(user, attr, v)
                user._changed = True

    def populate_groups_by_mapping(self, user, dn, conn, block, group_dns):
        '''Assign group to user based on a mapping from group DNs'''
        group_mapping = block['group_mapping']
        if not group_mapping:
            return
        if not user.pk:
            user.save()
            user._changed = False
        groups = user.groups.all()
        for dn, group_names in group_mapping:
            for group_name in group_names:
                group = self.get_group_by_name(block, group_name)
                if group is None:
                    continue
                # Add missing groups
                if dn in group_dns and group not in groups:
                    user.groups.add(group)
                # Remove extra groups
                elif dn not in group_dns and group in groups:
                    user.groups.remove(group)

    def get_ldap_group_dns(self, user, dn, conn, block, attributes):
        '''Retrieve group DNs from the LDAP by attributes (memberOf) or by
           filter.
        '''
        group_base_dn = block.get('group_basedn', block['basedn'])
        member_of_attribute = block['member_of_attribute']
        group_filter = block['group_filter']
        group_dns = set()
        if member_of_attribute:
            member_of_attribute = str(member_of_attribute)
            results = conn.search_s(dn, ldap.SCOPE_BASE, '', [member_of_attribute])
            group_dns.update(results[0][1].get(member_of_attribute, []))
        if group_filter:
            group_filter = str(group_filter)
            params = attributes.copy()
            params['user_dn'] = dn
            query = FilterFormatter().format(group_filter, **params)
            try:
                results = conn.search_s(group_base_dn, ldap.SCOPE_SUBTREE, query, [])
            except ldap.NO_SUCH_OBJECT:
                pass
            else:
                # ignore referrals by checking if bool(dn) is True
                group_dns.update(dn for dn, attributes in results if dn)
        return group_dns

    def populate_user_groups(self, user, dn, conn, block, attributes):
        group_dns = self.get_ldap_group_dns(user, dn, conn, block, attributes)
        log.debug('groups for dn %r: %r', dn, group_dns)
        self.populate_admin_flags_by_group(user, block, group_dns)
        self.populate_groups_by_mapping(user, dn, conn, block, group_dns)

    def get_group_by_name(self, block, group_name, create=None):
        '''Obtain a Django group'''
        if create is None:
            create = block['create_group']
        if create:
            group, created = Group.objects.get_or_create(name=group_name)
            return group
        else:
            try:
                return Group.objects.get(name=group_name)
            except Group.DoesNotExist:
                return None

    def populate_mandatory_groups(self, user, block):
        mandatory_groups = block.get('set_mandatory_groups')
        if not mandatory_groups:
            return
        if not user.pk:
            user.save()
            user._changed = False
        groups = user.groups.all()
        for group_name in mandatory_groups:
            group = self.get_group_by_name(block, group_name)
            if group is None:
                continue
            if group not in groups:
                user.groups.add(group)

    def populate_admin_fields(self, user, block):
        if block['is_staff'] is not None:
            if user.is_staff != block['is_staff']:
                user.is_staff = block['is_staff']
                user._changed = True
        if block['is_superuser'] is not None:
            if user.is_superuser != block['is_superuser']:
                user.is_superuser = block['is_superuser']
                user._changed = True

    def populate_user(self, user, dn, username, conn, block, attributes):
        self.populate_user_attributes(user, block, attributes)
        self.populate_admin_fields(user, block)
        self.populate_user_ou(user, dn, conn, block, attributes)
        self.update_user_identifiers(user, username, block, attributes)
        self.populate_mandatory_groups(user, block)
        self.populate_user_groups(user, dn, conn, block, attributes)

    def populate_user_ou(self, user, dn, conn, block, attributes):
        '''Assign LDAP user to an ou, the default one if ou_slug setting is
           None'''

        ou_slug = block['ou_slug']
        OU = get_ou_model()
        if ou_slug:
            ou_slug = unicode(ou_slug)
            try:
                ou = OU.objects.get(slug=ou_slug)
            except OU.DoesNotExist:
                raise ImproperlyConfigured('ou_slug value is wrong for ldap %r' % block['url'])
        else:
            ou = get_default_ou()
        if user.ou != ou:
            user.ou = ou
            user._changed = True

    @classmethod
    def attribute_name_from_external_id_tuple(cls, external_id_tuple):
        for attribute in external_id_tuple:
            if ':' in attribute:
                attribute = attribute.split(':', 1)[0]
            yield attribute

    @classmethod
    def get_ldap_attributes_names(cls, block):
        attributes = set()
        attributes.update(map(str, block['attributes']))
        for field in ('email_field', 'fname_field', 'lname_field'):
            if block[field]:
                attributes.add(block[field])
        for external_id_tuple in block['external_id_tuples']:
            attributes.update(cls.attribute_name_from_external_id_tuple(
                external_id_tuple))
        for from_at, to_at in block['attribute_mappings']:
            attributes.add(to_at)
        return list(set(map(str.lower, map(str, attributes))))

    @classmethod
    def get_ldap_attributes(cls, block, conn, dn):
        '''Retrieve some attributes from LDAP, add mandatory values then apply
           defined mappings between atrribute names'''
        attributes = cls.get_ldap_attributes_names(block)
        attribute_mappings = block['attribute_mappings']
        mandatory_attributes_values = block['mandatory_attributes_values']
        try:
            results = conn.search_s(dn, ldap.SCOPE_BASE, '(objectclass=*)', attributes)
        except ldap.LDAPError:
            log.exception('unable to retrieve attributes of dn %r', dn)
            return {}
        attribute_map = cls.normalize_ldap_results(results[0][1])
        # add mandatory attributes
        for key, mandatory_values in mandatory_attributes_values.iteritems():
            key = str(key)
            old = attribute_map.setdefault(key, [])
            new = set(old) | set(mandatory_values)
            attribute_map[key] = list(new)
        # apply mappings
        for from_attribute, to_attribute in attribute_mappings:
            from_attribute = str(from_attribute)
            if from_attribute not in attribute_map:
                continue
            to_attribute = str(to_attribute)
            old = attribute_map.setdefault(to_attribute, [])
            new = set(old) | set(attribute_map[from_attribute])
            attribute_map[to_attribute] = list(new)
        attribute_map['dn'] = dn
        return attribute_map

    @classmethod
    def external_id_to_filter(cls, external_id, external_id_tuple):
        '''Split the external id, decode it and build an LDAP filter from it
           and the external_id_tuple.
        '''
        splitted = external_id.split()
        if len(splitted) != len(external_id_tuple):
            return
        filters = zip(external_id_tuple, splitted)
        decoded = []
        for attribute, value in filters:
            quote = True
            if ':' in attribute:
                attribute, param = attribute.split(':')
                quote = 'noquote' not in param.split(',')
            if quote:
                decoded.append((attribute, urllib.unquote(value)))
            else:
                decoded.append((attribute, value.encode('utf-8')))
        filters = [filter_format('(%s=%s)', (a, b)) for a, b in decoded]
        return '(&{0})'.format(''.join(filters))

    def build_external_id(self, external_id_tuple, attributes):
        '''Build the exernal id for the user, use attribute that eventually
           never change like GUID or UUID.
        '''
        l = []
        for attribute in external_id_tuple:
            quote = True
            if ':' in attribute:
                attribute, param = attribute.split(':')
                quote = 'noquote' not in param.split(',')
            v = attributes[attribute]
            if isinstance(v, list):
                v = v[0]
            if isinstance(v, unicode):
                v = v.encode('utf-8')
            if quote:
                v = urllib.quote(v)
            l.append(v)
        return ' '.join(v for v in l)

    def lookup_by_username(self, username):
        User = get_user_model()
        try:
            log.debug('lookup using username %r', username)
            return LDAPUser.objects.prefetch_related('groups').get(username=username)
        except User.DoesNotExist:
            return

    def lookup_by_external_id(self, block, attributes):
        User = get_user_model()
        for eid_tuple in block['external_id_tuples']:
            external_id = self.build_external_id(eid_tuple, attributes)
            if not external_id:
                continue
            try:
                log.debug('lookup using external_id %r: %r', eid_tuple, external_id)
                return LDAPUser.objects.prefetch_related('groups').get(
                    userexternalid__external_id=external_id, userexternalid__source=block['realm'])
            except User.DoesNotExist:
                pass

    def lookup_existing_user(self, username, block, attributes):
        for lookup_type in block['lookups']:
            if lookup_type == 'username':
                return self.lookup_by_username(username)
            elif lookup_type == 'external_id':
                return self.lookup_by_external_id(block, attributes)

    def update_user_identifiers(self, user, username, block, attributes):
        # if username has changed and we propagate those changes, update it
        if block['update_username']:
            if user.username != username:
                old_username = user.username
                user.username = username
                user._changed = True
                log_msg = 'updating username from %r to %r'
                log.debug(log_msg, old_username, user.username)
        # if external_id lookup is used, update it
        if 'external_id' in block['lookups'] \
           and block.get('external_id_tuples') \
           and block['external_id_tuples'][0]:
            if not user.pk:
                user.save()
                user._changed = False
            external_id = self.build_external_id(
                block['external_id_tuples'][0],
                attributes)
            if external_id:
                new, created = UserExternalId.objects.get_or_create(
                    user=user, external_id=external_id, source=block['realm'])
                if block['clean_external_id_on_update']:
                    UserExternalId.objects \
                        .exclude(id=new.id) \
                        .filter(user=user, source=block['realm']) \
                        .delete()

    def _return_user(self, dn, password, conn, block, attributes=None):
        attributes = attributes or self.get_ldap_attributes(block, conn, dn)
        if attributes is None:
            # attributes retrieval failed
            return
        log.debug('retrieved attributes for %r: %r', dn, attributes)
        username = self.create_username(block, attributes)
        return self._return_django_user(dn, username, password, conn, block, attributes)

    def _return_django_user(self, dn, username, password, conn, block, attributes):
        user = self.lookup_existing_user(username, block, attributes)
        if user:
            log.debug('found existing user %r', user)
        else:
            user = LDAPUser(username=username)
            user.set_unusable_password()
        user.ldap_init(block, dn)
        user.keep_password(password)
        self.populate_user(user, dn, username, conn, block, attributes)
        if not user.pk or getattr(user, '_changed', False):
            user.save()
        user_login_success(user.get_username())
        return user

    def has_usable_password(self, user):
        return True

    def get_saml2_authn_context(self):
        return lasso.SAML2_AUTHN_CONTEXT_PASSWORD

    @classmethod
    def get_attribute_names(cls):
        names = set()
        for block in cls.get_config():
            names.update(cls.get_ldap_attributes_names(block))
            names.update(block['mandatory_attributes_values'].keys())
        return [(a, '%s (LDAP)' % a) for a in sorted(names)]

    @classmethod
    def get_users(cls):
        logger = logging.getLogger(__name__)
        for block in cls.get_config():
            conn = cls.get_connection(block)
            if conn is None:
                logger.warning(u'unable to synchronize with LDAP servers %r', block['url'])
                continue
            user_basedn = block.get('user_basedn') or block['basedn']
            user_filter = block['sync_ldap_users_filter'] or block['user_filter']
            user_filter = user_filter.replace('%s', '*')
            attrs = cls.get_ldap_attributes_names(block)
            users = conn.search_s(user_basedn, ldap.SCOPE_SUBTREE, user_filter, attrlist=attrs)
            backend = cls()
            for user_dn, data in users:
                # ignore referrals
                if not user_dn:
                    continue
                data = cls.normalize_ldap_results(data)
                data['dn'] = user_dn
                yield backend._return_user(user_dn, None, conn, block, data)

    @classmethod
    def ad_encoding(cls, s):
        '''Encode an unicode string for AD consumption as a password'''
        return (u'"{0}"'.format(s)).encode('utf-16-le')

    @classmethod
    def modify_password(cls, conn, block, dn, old_password, new_password):
        '''Change user password with adaptation for Active Directory'''
        if block['use_password_modify'] and not block['active_directory']:
            conn.passwd_s(dn, old_password or None, new_password)
        else:
            modlist = []
            if block['active_directory']:
                key = 'unicodePwd'
                value = cls.ad_encoding(new_password)
                if old_password:
                    modlist = [
                        (ldap.MOD_DELETE, key, [cls.ad_encoding(old_password)]),
                        (ldap.MOD_ADD, key, [value])
                    ]
                else:
                    modlist = [(ldap.MOD_REPLACE, key, [value])]
            else:
                key = 'userPassword'
                value = new_password.encode('utf-8')
                modlist = [(ldap.MOD_REPLACE, key, [value])]
            conn.modify_s(dn, modlist)
        log.debug('modified password for dn %r', dn)

    @classmethod
    def normalize_ldap_results(cls, attributes, encoding='utf-8'):
        new_attributes = {}
        for key in attributes:
            try:
                new_attributes[key.lower()] = map(lambda x: unicode(x, encoding), attributes[key])
            except UnicodeDecodeError:
                log.debug('unable to decode attribute %r as UTF-8, converting to base64', key)
                new_attributes[key.lower()] = map(base64.b64encode, attributes[key])
        return new_attributes

    @classmethod
    def get_connections(cls, block, credentials=()):
        '''Try each replicas, and yield successfull connections'''
        if not block['url']:
            raise ImproperlyConfigured("block['url'] must contain at least one url")
        for url in block['url']:
            for key, value in block['global_ldap_options'].iteritems():
                ldap.set_option(key, value)
            conn = ReconnectLDAPObject(url)
            if block['timeout'] > 0:
                conn.set_option(ldap.OPT_NETWORK_TIMEOUT, block['timeout'])
            conn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT,
                            getattr(ldap, 'OPT_X_TLS_' + block['require_cert'].upper()))
            if block['cacertfile']:
                conn.set_option(ldap.OPT_X_TLS_CACERTFILE, block['cacertfile'])
            if block['cacertdir']:
                conn.set_option(ldap.OPT_X_TLS_CACERTDIR, block['cacertdir'])
            if block['certfile']:
                conn.set_option(ldap.OPT_X_TLS_CERTFILE, block['certfile'])
            if block['keyfile']:
                conn.set_option(ldap.OPT_X_TLS_CERTFILE, block['keyfile'])
            for key, value in block['ldap_options']:
                conn.set_option(key, value)
            conn.set_option(ldap.OPT_REFERRALS, 1 if block['referrals'] else 0)
            # allow TLS options to be applied
            conn.set_option(ldap.OPT_X_TLS_NEWCTX, 0)
            try:
                if not url.startswith('ldaps://') and block['use_tls']:
                    try:
                        conn.start_tls_s()
                    except ldap.CONNECT_ERROR:
                        log.error('connection to %r failed when activating TLS, did you forget '
                                  'to declare the TLS certificate in /etc/ldap/ldap.conf ?', url)
                        continue
            except ldap.TIMEOUT:
                log.error('connection to %r timed out', url)
                continue
            except ldap.CONNECT_ERROR:
                log.error('connection to %r failed when activating TLS, did you forget to '
                          'declare the TLS certificate in /etc/ldap/ldap.conf ?', url)
                continue
            except ldap.SERVER_DOWN:
                if block['replicas']:
                    log.warning('ldap %r is down', url)
                else:
                    log.error('ldap %r is down', url)
                continue
            try:
                if credentials:
                    conn.bind_s(*credentials)
                elif block['bindsasl']:
                    sasl_mech, who, sasl_params = block['bindsasl']
                    handler_class = getattr(ldap.sasl, sasl_mech)
                    auth = handler_class(*sasl_params)
                    conn.sasl_interactive_bind_s(who, auth)
                elif block['binddn'] and block['bindpw']:
                    conn.bind_s(block['binddn'], block['bindpw'])
                yield conn
            except ldap.INVALID_CREDENTIALS:
                log.error('admin bind failed on %s: invalid credentials', url)
                if block['replicas']:
                    break
            except ldap.INVALID_DN_SYNTAX:
                log.error('admin bind failed on %s: invalid dn syntax %r', url, who)
                if block['replicas']:
                    break

    @classmethod
    def get_connection(cls, block, credentials=()):
        '''Try to get at least one connection'''
        for conn in cls.get_connections(block, credentials=credentials):
            return conn

    @classmethod
    def update_default(cls, block):
        '''Add missing key to block based on default values'''
        for key in block:
            if key not in cls._VALID_CONFIG_KEYS:
                raise ImproperlyConfigured(
                    '"{}" : invalid LDAP_AUTH_SETTINGS key, available are {}'.format(
                        key, cls._VALID_CONFIG_KEYS))

        for r in cls._REQUIRED:
            if r not in block:
                raise ImproperlyConfigured(
                    'LDAP_AUTH_SETTINGS: missing required configuration option %r' % r)

        for d in cls._DEFAULTS:
            if d not in block:
                block[d] = cls._DEFAULTS[d]
            else:
                if isinstance(cls._DEFAULTS[d], six.string_types):
                    if not isinstance(block[d], six.string_types):
                        raise ImproperlyConfigured(
                            'LDAP_AUTH_SETTINGS: attribute %r must be a string' % d)
                    try:
                        block[d] = str(block[d])
                    except UnicodeEncodeError:
                        raise ImproperlyConfigured(
                            'LDAP_AUTH_SETTINGS: attribute %r must be a string' % d)
                if isinstance(cls._DEFAULTS[d], bool) and not isinstance(block[d], bool):
                    raise ImproperlyConfigured(
                        'LDAP_AUTH_SETTINGS: attribute %r must be a boolean' % d)
                if (isinstance(cls._DEFAULTS[d], (list, tuple))
                        and not isinstance(block[d], (list, tuple))):
                    raise ImproperlyConfigured(
                        'LDAP_AUTH_SETTINGS: attribute %r must be a list or a tuple' % d)
                if isinstance(cls._DEFAULTS[d], dict) and not isinstance(block[d], dict):
                    raise ImproperlyConfigured(
                        'LDAP_AUTH_SETTINGS: attribute %r must be a dictionary' % d)
                if not isinstance(cls._DEFAULTS[d], bool) and d in cls._REQUIRED and not block[d]:
                    raise ImproperlyConfigured(
                        'LDAP_AUTH_SETTINGS: attribute %r is required but is empty')
        for i in cls._TO_ITERABLE:
            if isinstance(block[i], six.string_types):
                block[i] = (block[i],)
        # lowercase LDAP attribute names
        block['external_id_tuples'] = map(
            lambda t: map(str.lower, map(str, t)), block['external_id_tuples'])
        block['attribute_mappings'] = map(
            lambda t: map(str.lower, map(str, t)), block['attribute_mappings'])
        for key in cls._TO_LOWERCASE:
            # we handle strings, list of strings and list of list or tuple whose first element is a
            # string
            if isinstance(block[key], six.string_types):
                block[key] = str(block[key]).lower()
            elif isinstance(block[key], (list, tuple)):
                new_seq = []
                for elt in block[key]:
                    if isinstance(elt, six.string_types):
                        elt = str(elt).lower()
                    elif isinstance(elt, (list, tuple)):
                        elt = list(elt)
                        elt[0] = str(elt[0]).lower()
                        elt = tuple(elt)
                    new_seq.append(elt)
                block[key] = tuple(new_seq)
            elif isinstance(block[key], dict):
                newdict = {}
                for subkey in block[key]:
                    newdict[str(subkey).lower()] = block[key][subkey]
                block[key] = newdict
            else:
                raise NotImplementedError(
                    'LDAP setting %r cannot be converted to lowercase setting, its type is %r'
                    % (key, type(block[key])))
        # Want to randomize our access, otherwise what's the point of having multiple servers?
        block['url'] = list(block['url'])
        if block['shuffle_replicas']:
            random.shuffle(block['url'])


class LDAPBackendPasswordLost(LDAPBackend):
    def authenticate(self, user=None, **kwargs):
        if not user:
            return
        config = self.get_config()
        if not config:
            return
        for user_external_id in user.userexternalid_set.all():
            external_id = user_external_id.external_id
            for block in config:
                if user_external_id.source != unicode(block['realm']):
                    continue
                for external_id_tuple in block['external_id_tuples']:
                    conn = self.ldap_backend.get_connection(block)
                    try:
                        if external_id_tuple == ('dn:noquote',):
                            dn = external_id
                            results = conn.search_s(dn, ldap.SCOPE_BASE)
                        else:
                            ldap_filter = self.external_id_to_filter(external_id, external_id_tuple)
                            results = conn.search_s(block['basedn'],
                                                    ldap.SCOPE_SUBTREE, ldap_filter)
                            if not results:
                                log.error(
                                    'unable to find user %r based on external id %s',
                                    unicode(user), external_id)
                                continue
                            dn = results[0][0]
                    except ldap.LDAPError:
                        log.error(
                            'unable to find user %r based on external id %s', unicode(user),
                            external_id)
                        continue
                    return self._return_user(dn, None, conn, block)

LDAPUser.ldap_backend = LDAPBackend
LDAPBackendPasswordLost.ldap_backend = LDAPBackend
