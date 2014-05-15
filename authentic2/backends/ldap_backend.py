try:
    import ldap
    import ldap.modlist
    import ldap.sasl
    from ldap.filter import filter_format
except ImportError:
    ldap = None
import logging
import random
import urlparse
import pickle
import base64
import hashlib

# code copied from http://www.amherst.k12.oh.us/django-ldap.html

log = logging.getLogger(__name__)

from django.core.exceptions import ImproperlyConfigured
from django.conf import settings
from django.contrib.auth.models import Group

from ..cache import get_shared_cache
from ..decorators import to_list

try:
    import lasso
except ImportError:
    pass


from ..compat import get_user_model


from ..models import UserExternalId

_DEFAULTS = {
    'binddn': None,
    'bindpw': None,
    'bindsasl': (),
    'user_dn_template': None,
    'user_filter': 'uid=%s',
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
    'use_for_data' : None,
    'bind_with_username': False,
    # always use the first URL to build the external id
    'use_first_url_for_external_id': True,
    # do not try to get a Django user from the LDAP user
    # it's incompatible with a lot of Django applications, the
    # django.contrib.admin for example
    'transient': True,
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
    'attributes': [],
    # default value for some attributes
    'mandatory_attributes_values': {},
    # mapping from LDAP attributes name to other names
    'attribute_mappings': [],
    # realm for selecting an ldap configuration or formatting usernames
    'realm': 'ldap',
    # template for building username
    'username_template': '{username}@{realm}',
    # allow to match multiple user records
    'multimatch': True,
    # update username on all login, use with CAUTION !! only if you know that
    # generated username are unique
    'update_username': False,
    # lookup existing user with dn
    'lookups': ('username', 'dn'),
    # keep password around so that Django authentification also work
    'keep_password': True,
    'limit_to_realm': True,
}

_REQUIRED = ('url', 'basedn')
_TO_ITERABLE = ('url', 'groupsu', 'groupstaff', 'groupactive')

def get_connection(block, credentials=()):
    if not block['url']:
        raise ImproperlyConfigured("block['url'] must contain at least one url")
    for url in block['url']:
        conn = ldap.initialize(url)
        conn.set_option(ldap.OPT_REFERRALS, 1 if block['referrals'] else 0)
        try:
            conn.whoami_s()
        except ldap.SERVER_DOWN:
            if block['replicas']:
                log.warning('ldap %r is down', url)
            else:
                log.error('ldap %r is down', url)
            continue
        try:
            if credentials:
                conn.bind_s(*credentials)
            elif block['binddn'] and block['bindpw']:
                conn.bind_s(block['binddn'], block['bindpw'])
            break
        except ldap.INVALID_CREDENTIALS:
            if block['replicas']:
                return None
    else:
        return None
    return conn

def ad_encoding(s):
    '''Encode an unicode string for AD consumption as a password'''
    return (u'"{0}"'.format(s)).encode('utf-16-le')

def modify_password(conn, block, dn, old_password, new_password):
    '''Change user password with adaptation for Active Directory'''
    if block['active_directory']:
        old_entry = { 'unicodePwd': [ ad_encoding(old_password) ] }
        new_entry = { 'unicodePwd': [ ad_encoding(new_password) ] }
    else:
        old_entry = { 'userPassword': [ old_password.encode('utf-8') ] }
        new_entry = { 'userPassword': [ new_password.encode('utf-8') ] }
    conn.modify_s(dn, ldap.modlist.modifyModlist(old_entry, new_entry))
    log.debug('modified password for dn %r', dn)

def unicode_dict_of_list(attributes, encoding='utf-8'):
    for key in attributes:
        try:
            attributes[key] = map(lambda x: unicode(x, encoding), attributes[key])
        except UnicodeDecodeError:
            log.warning('unable to decode attribute %r to UTF-8', key)
    return attributes

class LDAPException(Exception):
    pass

class LDAPUser(get_user_model()):
    attributes = {}

    class Meta:
        proxy = True

    def ldap_init(self, block, dn, password, attributes, transient=False):
        self.block = block
        self.dn = dn
        self.is_active = True
        self.set_ldap_password(password)
        self.attributes = attributes
        self.transient = transient

    def set_ldap_password(self, password):
        shared_cache = get_shared_cache('ldap')
        shared_cache.set(self.get_ldap_password_cache_key(), password, 86400)

    def get_cache_key(self):
        return hashlib.md5(self.dn).hexdigest()

    def get_ldap_password_cache_key(self):
        return 'ldap-password-{0}'.format(self.get_cache_key())

    def get_password(self):
        shared_cache = get_shared_cache('ldap')
        password = shared_cache.get(self.get_ldap_password_cache_key())
        if password is None:
            raise LDAPException('missing password for dn %r', self.dn)
        return password

    def set_password(self, new_password):
        old_password = self.get_password()
        if old_password != new_password:
            conn = self.get_connection()
            modify_password(conn, self.block, self.dn, self.get_password(),
                    new_password)
        self.set_ldap_password(new_password)
        super(LDAPUser, self).set_password(new_password)

    def get_connection(self):
        return get_connection(self.block, (self.dn, self.get_password()))

    def get_attributes(self):
        return self.attributes

    def save(self, *args, **kwargs):
        if self.transient:
            return
        if hasattr(self, 'keep_pk'):
            pk = self.pk
            self.pk = self.keep_pk
        super(LDAPUser, self).save(*args, **kwargs)
        if hasattr(self, 'keep_pk'):
            self.pk = pk

class LDAPBackendError(Exception):
    pass


class LDAPBackendError(RuntimeError):
    pass

class LDAPBackend():
    @classmethod
    @to_list
    def get_realms(self):
        config = self.get_config()
        for block in config:
            yield block['realm']

    @classmethod
    def get_config(self):
        if isinstance(settings.LDAP_AUTH_SETTINGS[0], dict):
            blocks = settings.LDAP_AUTH_SETTINGS
        else:
            blocks = (self._parse_simple_config(),)
        # First get our configuration into a standard format
        for block in blocks:
            for r in _REQUIRED:
                if r not in block:
                    raise ImproperlyConfigured('LDAP_AUTH_SETTINGS: missing required configuration option %r' % r)

            for d in _DEFAULTS:
                if d not in block:
                    block[d] = _DEFAULTS[d]
                else:
                    if isinstance(_DEFAULTS[d], basestring):
                        if not isinstance(block[d], basestring):
                            raise ImproperlyConfigured('LDAP_AUTH_SETTINGS: '
                                    'attribute %r must be a string' % d)
                        try:
                            block[d] = str(block[d])
                        except UnicodeEncodeError:
                            raise ImproperlyConfigured('LDAP_AUTH_SETTINGS: '
                                    'attribute %r must be a string' % d)
                    if isinstance(_DEFAULTS[d], bool) and not isinstance(block[d], bool):
                        raise ImproperlyConfigured('LDAP_AUTH_SETTINGS: '
                                'attribute %r must be a boolean' % d)
                    if isinstance(_DEFAULTS[d], (list, tuple)) and not isinstance(block[d], (list, tuple)):
                        raise ImproperlyConfigured('LDAP_AUTH_SETTINGS: '
                                'attribute %r must be a list or a tuple' % d)
                    if isinstance(_DEFAULTS[d], dict) and not isinstance(block[d], dict):
                        raise ImproperlyConfigured('LDAP_AUTH_SETTINGS: '
                                'attribute %r must be a dictionary' % d)
                    if not isinstance(_DEFAULTS[d], bool) and d in _REQUIRED and not block[d]:
                        raise ImproperlyConfigured('LDAP_AUTH_SETTINGS: '
                                'attribute %r is required but is empty')
            for i in _TO_ITERABLE:
                if isinstance(block[i], basestring):
                    block[i] = (block[i],)

            # Want to randomize our access, otherwise what's the point of having multiple servers?
            block['url'] = list(block['url'])
            if block['shuffle_replicas']:
                random.shuffle(block['url'])
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
        from ldap.dn import escape_dn_chars
        if block['timeout'] != -1:
            for opt in ('NETWORK_TIMEOUT', 'TIMELIMIT', 'TIMEOUT'):
                ldap.set_option(getattr(ldap, 'OPT_%s' % opt), block['timeout'])
        utf8_username = username.encode('utf-8')
        utf8_password = password.encode('utf-8')

        for uri in block['url']:
            log.debug('try to bind user on %r', uri)
            conn = ldap.initialize(uri)
            conn.set_option(ldap.OPT_REFERRALS, 1 if block['referrals'] else 0)
            authz_ids = []
            user_basedn = block.get('user_basedn', block['basedn'])

            try:
                # if necessary bind as admin
                self.try_admin_bind(conn, block)
                if block['user_dn_template']:
                    template = str(block['user_dn_template'])
                    escaped_username = escape_dn_chars(username)
                    authz_ids.append(template.format(username=escaped_username))
                else:
                    try:
                        if block.get('bind_with_username'):
                            authz_ids.append(utf8_username)
                        elif block['user_filter']:
                            try:
                                query = filter_format(block['user_filter'], (utf8_username,))
                            except TypeError, e:
                                log.error('user_filter syntax error %r: %s',
                                        block['user_filter'], e)
                                return
                            log.debug('looking up dn for username %r using '
                                    'query %r', username, query)
                            results = conn.search_s(user_basedn, ldap.SCOPE_SUBTREE, query)
                            # remove search references
                            results = [ result for result in results if result[0] is not None]
                            if len(results) == 0:
                                log.debug('user lookup failed: no entry found, %s' % query)
                            elif not block['multimatch'] and len(results) > 1:
                                log.error('user lookup failed: too many (%d) '
                                        'entries found: %s', len(results), query)
                            else:
                                authz_ids.extend(result[0] for result in results)
                        else:
                            raise NotImplementedError
                    except ldap.NO_SUCH_OBJECT:
                        log.error('user lookup failed: basedn %s not found',
                                user_basedn)
                        if block['replicas']:
                            break
                        continue
                    except ldap.LDAPError, e:
                        raise
                        log.error('user lookup failed: with query %r got error '
                                '%s', username, query, e)
                        continue
                if not authz_ids:
                    continue

                try:
                    for authz_id in authz_ids:
                        try:
                            conn.simple_bind_s(authz_id, utf8_password)
                            break
                        except ldap.INVALID_CREDENTIALS:
                            pass
                    else:
                        log.debug('user bind failed: invalid credentials' % uri)
                        if block['replicas']:
                            break
                        continue
                except ldap.NO_SUCH_OBJECT:
                    # should not happen as we just searched for this object !
                    log.error('user bind failed: authz_id not found %s' % ', '.join(authz_ids))
                    if block['replicas']:
                        break
                return self._return_user(uri, authz_id, username, password, conn, block)
            except ldap.SERVER_DOWN:
                log.error('ldap authentication error: %r is down', uri)
            finally:
                del conn
        return None

    def get_user(self, user_id):
        pickle_dump = user_id.split('!', 1)[1]
        user = pickle.loads(base64.b64decode(pickle_dump))
        if not user_id.startswith('transient!'):
            try:
                user.__dict__.update(LDAPUser.objects.get(pk=user.pk).__dict__)
            except LDAPUser.DoesNotExist:
                return None
        return user

    @classmethod
    def _parse_simple_config(self):
        if len(settings.LDAP_AUTH_SETTINGS) < 2:
            raise LDAPBackendError('In a minimal configuration, you must at least specify url and user DN')
        return {'url': settings.LDAP_AUTH_SETTINGS[0], 'basedn': settings.LDAP_AUTH_SETTINGS[1]}

    def backend_name(self):
        return '%s.%s' % (__name__, self.__class__.__name__)

    def build_ldap_external_id(self, uri, dn, block):
        if block['use_first_url_for_external_id']:
            uri = block['url'][0]
        parsed_uri = urlparse.urlparse(uri)
        return '{scheme}://{netloc}/{dn}??one?'.format(scheme=parsed_uri.scheme,
                netloc=parsed_uri.netloc, dn=dn)

    def create_username(self, uri, dn, username, password, conn, block, attributes):
        '''Build a username using the configured template'''
        username_template = unicode(block['username_template'])
        return username_template.format(username=username, dn=dn, uri=uri,
                block=block, realm=block['realm'], **attributes)

    def create_user(self, uri, dn, username, password, conn, block, attributes):
        User = get_user_model()
        user = LDAPUser(**{User.USERNAME_FIELD: username})
        return user

    def populate_user_attributes(self, user, uri, dn, conn, block, attributes):
        for legacy_attribute, legacy_field in (('email', 'email_field'), 
                ('first_name', 'fname_field'), ('last_name', 'lname_field')):
            ldap_attribute = block[legacy_field]
            if not ldap_attribute:
                break
            if ldap_attribute in attributes:
                value = attributes[ldap_attribute][0]
            else:
                value = u''
            setattr(user, legacy_attribute, value)
        user.attributes = attributes

    def try_admin_bind(self, conn, block):
        try:
            if block['bindsasl']:
                sasl_mech, who, sasl_params = block['bindsasl']
                handler_class = getattr(ldap.sasl, sasl_mech)
                auth = handler_class(*sasl_params)
                conn.sasl_interactive_bind_s(who, auth)
            elif block['binddn'] and block['bindpw']:
                conn.simple_bind_s(block['binddn'], block['bindpw'])
        except ldap.INVALID_CREDENTIALS:
            log.error('admin bind failed: invalid credentials (%r, %r)',
                    block['binddn'], '*hidden*')
        except ldap.INVALID_DN_SYNTAX:
            log.error('admin bind failed: invalid dn syntax %r', who)
        else:
            return True
        return False

    def populate_admin_flags_by_group(self, user, uri, dn, conn, block, group_dns):
        '''Attribute admin flags based on groups.

           It supersedes is_staff, is_superuser and is_active.'''
        for g, attr in (('groupsu', 'is_superuser'), ('groupstaff', 'is_staff'), ('groupactive', 'is_active')):
            group_dns_to_match = block[g]
            if not group_dns_to_match:
                continue
            for group_dn in group_dns_to_match:
                if group_dn in group_dns:
                    setattr(user, attr, True)
                    break
            else:
                setattr(user, attr, False)

    def populate_groups_by_mapping(self, user, uri, dn, conn, block, group_dns):
        '''Assign group to user based on a mapping from group DNs'''
        group_mapping = block['group_mapping']
        if not group_mapping:
            return
        for dn, group_names in group_mapping:
            method = user.groups.add if dn in group_dns else user.groups.remove
            for group_name in group_names:
                group = self.get_group_by_name(block, group_name)
                if group is not None:
                    try:
                        method(group)
                    except KeyError:
                        pass

    def get_ldap_group_dns(self, user, uri, dn, conn, block):
        '''Retrieve group DNs from the LDAP by attributes (memberOf) or by
           filter.
        '''
        group_base_dn = block.get('group_basedn', block['basedn'])
        member_of_attribute = block['member_of_attribute']
        group_filter = block['group_filter']
        group_dns = set()
        if member_of_attribute:
            results = conn.search_s(dn, ldap.SCOPE_BASE, '', [member_of_attribute])
            group_dns.update(results[0][1].get(member_of_attribute, []))
        if group_filter:
            try:
                results = conn.search_s(group_base_dn, ldap.SCOPE_SUBTREE,
                        group_filter.format(user_dn=dn), [])
            except ldap.NO_SUCH_OBJECT:
                pass
            group_dns.update(dn for dn, attributes in results)
        return group_dns

    def populate_user_groups(self, user, uri, dn, conn, block):
        group_dns = self.get_ldap_group_dns(user, uri, dn, conn, block)
        log.debug('groups for dn %r: %r', dn, group_dns)
        self.populate_admin_flags_by_group(user, uri, dn, conn, block, group_dns)
        self.populate_groups_by_mapping(user, uri, dn, conn, block, group_dns)


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

    def populate_mandatory_groups(self, user, uri, dn, conn, block):
        mandatory_groups = block.get('set_mandatory_groups')
        if not mandatory_groups:
            return
        for group_name in mandatory_groups:
            group = self.get_group_by_name(block, group_name)
            if group:
                user.groups.add(group)

    def populate_admin_fields(self, user, uri, dn, conn, block):
        if block['is_staff'] is not None:
            user.is_staff = block['is_staff']
        if block['is_superuser'] is not None:
            user.is_superuser = block['is_superuser']

    def populate_user(self, user, uri, dn, username, conn, block, attributes):
        self.update_user_identifiers(user, uri, dn, username, conn, block,
                attributes)
        self.populate_user_attributes(user, uri, dn, conn, block, attributes)
        self.populate_admin_fields(user, uri, dn, conn, block)
        self.populate_mandatory_groups(user, uri, dn, conn, block)
        self.populate_user_groups(user, uri, dn, conn, block)

    def get_ldap_attributes(self, uri, dn, conn, block):
        '''Retrieve some attributes from LDAP, add mandatory values then apply
           defined mappings between atrribute names'''
        attributes = map(str, block['attributes'])
        attribute_mappings = block['attribute_mappings']
        mandatory_attributes_values = block['mandatory_attributes_values']
        try:
            results = conn.search_s(dn, ldap.SCOPE_BASE, '(objectclass=*)', attributes)
        except ldap.LDAPError, e:
            log.warning('unable to retrieve attributes of dn %r: %s', dn, e)
        attribute_map = results[0][1]
        attribute_map = unicode_dict_of_list(attribute_map)
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
        return attribute_map

    def lookup_existing_user(self, uri, dn, username, password, conn, block, attributes):
        User = get_user_model()
        for lookup_type in block['lookups']:
            if lookup_type == 'username':
                try:
                    log.debug('lookup using username %r', username)
                    return LDAPUser.objects.get(**{User.USERNAME_FIELD: username})
                except User.DoesNotExist:
                    pass
            elif lookup_type == 'dn':
                try:
                    log.debug('lookup using dn %r', dn)
                    return LDAPUser.objects.get(userexternalid__external_id=dn,
                            userexternalid__source=block['realm'])
                except User.DoesNotExist:
                    pass

    def update_user_identifiers(self, user, uri, dn, username, conn,
            block, attributes):
        if block['transient']:
            return
        # if username has changed and we propagate those changes, update it
        if block['update_username']:
            if user.username != username:
                log_msg = 'updating username from %r to %r'
                log.debug(log_msg, user.username, username)
                user.username = username
                user.save()
        # if dn lookup is used, update it
        if 'dn' in block['lookups']:
            if not user.pk:
                user.save()
            UserExternalId.objects.get_or_create(user=user, external_id=dn,
                    source=block['realm'])

    def _return_user(self, uri, dn, username, password, conn, block):
        attributes = self.get_ldap_attributes(uri, dn, conn, block)
        username = self.create_username(uri, dn, username, password, conn,
                block, attributes)
        log.debug('retrieved attributes for %r: %r', dn, attributes)
        if block['transient']:
            return self._return_transient_user(uri, dn, username, password,
                    conn, block, attributes)
        else:
            return self._return_django_user(uri, dn, username, password, conn,
                    block, attributes)

    def _return_transient_user(self, uri, dn, username, password, conn, block, attributes):
        user = LDAPUser(username=username)
        user.ldap_init(block, dn, password, attributes, transient=True)
        self.populate_user(user, uri, dn, username, conn, block, attributes)
        user.set_password(password)
        user.pk = 'transient!{0}'.format(base64.b64encode(pickle.dumps(user)))
        return user

    def _return_django_user(self, uri, dn, username, password, conn, block, attributes):
        user = self.lookup_existing_user(uri, dn, username, password, conn, block, attributes)
        if user:
            log.debug('found existing user %r', user)
        else:
            user = self.create_user(uri, dn, username, password, conn, block, attributes)
            log.debug('created user %r', user)
        user.ldap_init(block, dn, password, attributes)
        if block['keep_password']:
            user.set_password(password)
        else:
            user.set_unusable_password()
        self.populate_user(user, uri, dn, username, conn, block, attributes)
        user.save()
        user.keep_pk = user.pk
        user.pk = 'persistent!{0}'.format(base64.b64encode(pickle.dumps(user)))
        return user

    def has_usable_password(self, user):
        return True

    def get_saml2_authn_context(self):
        return lasso.SAML2_AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT
