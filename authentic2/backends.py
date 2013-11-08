import ldap
import ldap.modlist
import ldap.sasl
from ldap.filter import filter_format
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
from django.contrib.auth.models import Group, AbstractUser, Permission
from django.db import IntegrityError

from .cache import get_shared_cache

try:
    import lasso
except ImportError:
    pass


from .compat import get_user_model


from .models import UserExternalId

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
    'timeout': 1,
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
    'is_superuser': False,
    # all users from this LDAP are staff
    'is_staff': False,
    # all users from this LDAP are active
    'is_active': True,
    # create missing group if needed
    'create_group': False,
}

_REQUIRED = ('url', 'basedn')
_TO_ITERABLE = ('url', 'groupsu', 'groupstaff', 'groupactive')

def get_connection(block, credentials=()):
    if not block['url']:
        raise ImproperlyConfigured("block['url'] must contain at least one url")
    for url in block['url']:
        conn = ldap.initialize(url)
        try:
            authzid = conn.whoami_s()
        except ldap.SERVER_DOWN:
            if block['replicas']:
                log.warning('ldap %r is down', uri)
            else:
                log.error('ldap %r is down', uri)
            continue
        try:
            if credentials:
                conn.bind_s(*credentials)
            elif block['binddn'] and block['bindpw']:
                conn.bind_s(blockp['binddn'], block['bindpw'])
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
    results = conn.search_s(dn, ldap.SCOPE_BASE)
    if block['active_directory']:
        old_entry = { 'unicodePwd': [ ad_encoding(old_password) ] }
        new_entry = { 'unicodePwd': [ ad_encoding(new_password) ] }
    else:
        old_entry = { 'userPassword': [ old_password.encode('utf-8') ] }
        new_entry = { 'userPassword': [ new_password.encode('utf-8') ] }
    conn.modify_s(dn, ldap.modlist.modifyModlist(old_entry, new_entry))
    log.debug('modified password for dn %r', dn)


class LDAPException(Exception):
    pass

class LDAPUser(object):
    is_staff = False
    is_superuser = False

    def __init__(self, block, dn, password):
        self.block = block
        self.dn = dn
        self.is_active = True
        self.set_ldap_password(password)
        self.groups = set()

    def set_ldap_password(self, password):
        shared_cache = get_shared_cache('ldap')
        shared_cache.set(self.get_ldap_password_cache_key(), password)

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

    def get_username(self):
        return self.dn

    def get_full_name(self):
        block = self.block
        if block['fname_field'] and block['lname_field']:
            return u'{first_name} {last_name}'.format(**self.__dict__)
        if block['email_field']:
            return self.email
        return self.get_username()

    def get_short_name(self):
        block = self.block
        if block['fname_field']:
            return self.first_name
        if block['email_field']:
            return self.email
        dn = self.dn
        l = dn.split(',', 1)[0].split('=')
        if len(l) > 1:
            return l[1]
        return l[0]

    def is_authenticated(self):
        return True

    def is_anonymous(self):
        return False

    def set_password(self, new_password):
        conn = self.get_connection()
        modify_password(conn, self.block, self.dn, self.get_password(),
                new_password)
        self.set_ldap_password(new_password)

    def set_unusable_password(self):
        raise NotImplementedError

    def has_usable_password(self):
        return True

    def get_connection(self):
        return get_connection(self.block, (self.dn, self.get_password()))

    def save(self, **kwargs):
        pass

    def get_group_permissions(self, obj=None):
        if not hasattr(self, '_group_perm_cache'):
            if self.is_superuser:
                perms = Permission.objects.all()
            else:
                group_pks = (group.pk for group in self.groups)
                perms = Permission.objects.filter(group__pk__in=group_pks)
            perms = perms.values_list('content_type__app_label', 'codename').order_by()
            self._group_perm_cache = set(["%s.%s" % (ct, name) for ct, name in perms])
        return self._group_perm_cache

    def get_all_permissions(self, obj=None):
        return self.get_group_permissions(obj)

    def has_perm(self, perm, obj=None):
        if not self.is_active:
            return False
        return perm in self.get_all_permissions(obj)

    def has_perms(self, perm_list, obj=None):
        pass

    def has_module_perms(self, app_label):
        if not self.is_active:
            return False
        for perm in self.get_all_permissions():
            if perm[:perm.index('.')] == app_label:
                return True
        return False

    def get_principal(self):
        return self.dn


class LDAPBackendError(Exception):
    pass


class LDAPBackendError(RuntimeError):
    pass

class LDAPBackend():
    def get_blocks(self):
        if isinstance(settings.LDAP_AUTH_SETTINGS[0], dict):
            log.debug('Using complex settings')
            blocks = settings.LDAP_AUTH_SETTINGS
        else:
            log.debug('Using simple settings')
            blocks = (self._parse_simple_config(),)
        return blocks

    def authenticate(self, username=None, password=None):
        if username is None or password is None:
            return None

        blocks = self.get_blocks()
        # First get our configuration into a standard format
        for block in blocks:
            for r in _REQUIRED:
                if r not in block:
                    raise ImproperlyConfigured('LDAP_AUTH_SETTINGS: missing required configuration option %r' % r)

            for d in _DEFAULTS:
                if d not in block:
                    block[d] = _DEFAULTS[d]
                else:
                    if isinstance(_DEFAULTS[d], str) and not isinstance(block[d], str):
                        raise ImproperlyConfigured('LDAP_AUTH_SETTINGS: '
                                'attribute %r must be a string' % d)
                    if isinstance(_DEFAULTS[d], bool) and not isinstance(block[d], bool):
                        raise ImproperlyConfigured('LDAP_AUTH_SETTINGS: '
                                'attribute %r must be a boolean' % d)

            for i in _TO_ITERABLE:
                if isinstance(block[i], basestring):
                    block[i] = (block[i],)

            # Want to randomize our access, otherwise what's the point of having multiple servers?
            block['url'] = list(block['url'])
            if block['shuffle_replicas']:
                random.shuffle(block['url'])

        # Now we can try to authenticate
        for block in blocks:
            try:
                user = self.authenticate_block(block, username, password)
                if user is not None:
                    return user
            except:
                log.exception('unexpected exception')
                raise

    def authenticate_block(self, block, username, password):
        for opt in ('NETWORK_TIMEOUT', 'TIMELIMIT', 'TIMEOUT'):
            ldap.set_option(getattr(ldap, 'OPT_%s' % opt), block['timeout'])
        utf8_username = username.encode('utf-8')
        utf8_password = password.encode('utf-8')

        for uri in block['url']:
            log.debug('try to bind user on %r', uri)
            conn = ldap.initialize(uri)
            authz_id = None
            user_basedn = block.get('user_basedn', block['basedn'])

            try:
                # if necessary bind as admin
                self.try_admin_bind(conn, block)
                if block['user_dn_template']:
                    authzid = block['user_dn_template'].format(username=username)
                else:
                    try:
                        if block.get('bind_with_username'):
                            authz_id = utf8_username
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
                            if len(results) == 0:
                                log.debug('user bind failed: not entry found')
                            elif len(results) > 1:
                                log.warning('user bind failed: too many (%d) '
                                        'entries found', len(results))
                            else:
                                authz_id = results[0][0]
                        else:
                            raise NotImplementedError
                    except ldap.NO_SUCH_OBJECT:
                        log.error('user bind failed: unable to lookup user '
                                'basedn %s not found', user_basedn)
                        if block['replicas']:
                            break
                        continue
                    except ldap.LDAPError, e:
                        log.error('user bind failed: unable to lookup user %r: '
                                '%s', username, e)
                        continue
                if authz_id is None:
                    continue
                try:
                    conn.simple_bind_s(authz_id, utf8_password)
                except ldap.INVALID_CREDENTIALS:
                    log.debug('user bind failed: invalid credentials' % uri)
                    if block['replicas']:
                        break
                    continue
                except ldap.LDAPError, e:
                    log.error('Got error from LDAP library: %s' % str(e))
                    return None
                return self._return_user(uri, authz_id, username, password, conn, block)
            finally:
                del conn
        return None

    def get_user(self, user_id):
        if hasattr(user_id, 'startswith') and user_id.startswith('transient!'):
            user = pickle.loads(base64.b64decode(user_id[len('transient!'):]))
        else:
            try:
                user = get_user_model().objects.get(pk=user_id)
            except:
                pass
            else:
                shared_cache = get_shared_cache('ldap')
                uri, dn, username, password, block = shared_cache.get('ldap-pk-{0}'.format(user_id))
                user.ldap_uri = uri
                user.ldap_dn = dn
                user.ldap_username = username
                user.ldap_password = password
                user.ldap_block = block
        return user

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

    def create_user(self, uri, dn, username, password, conn, block):
        User = get_user_model()
        new_user_username = username
        count = 0
        while True:
            try:
                user = User.objects.create(username=new_user_username)
                break
            except IntegrityError:
                new_user_username = u'{0}-{1}'.format(username, count)
                count += 1
        if block['replicas']:
            uri = block['url'][0]
        UserExternalId.objects.create(user=user, source=uri, external_id=dn)
        user.set_unusable_password()
        user.save()
        return user

    def populate_user_attributes(self, user, uri, dn, conn, block):
        try:
            results = conn.search_s(dn, ldap.SCOPE_BASE, '(objectclass=*)',
                    [block['email_field'], block['fname_field'],
                        block['lname_field']])
        except ldap.LDAPError, e:
            log.warning('unable to retrieve attributes of user %r with dn %r '
                    'from server %r: %s', username, dn, uri, e)
        if len(results) > 1:
            log.warning('unable to retrieve attributes of user %r with dn %r '
                    'from server %r: too many records', username, dn, uri)
        attributes = results[0][1]
        ldap_data = {}
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
            log.error('admin bind on %r failed: invalid credentials (%r, %r)',
                    uri, block['binddn'], '*hidden*')
        except ldap.INVALID_DN_SYNTAX:
            log.error('admin bind on %r failed: invalid dn syntax %r', uri,
                    who)
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
                group = self.get_group_by_name(group_name)
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


    def get_group_by_name(self, group_name, create=None):
        '''Obtain a Django group'''
        if create is None:
            create = block['create_group']
        if create:
            group, created = Group.objects.get_or_create(name=group_name)
            return group
        else:
            try:
                return Group.objects.get(name=group_name)
            except Group.ObjectDoesNotExist:
                return None

    def populate_mandatory_groups(self, user, uri, dn, conn, block):
        mandatory_groups = block.get('set_mandatory_groups')
        if not mandatory_groups:
            return
        for group_name in mandatory_groups:
            group = self.get_group_by_name(django_group_name)
            if group:
                user.groups.add(group)

    def populate_admin_fields(self, user, uri, dn, conn, block):
        user.is_active = block['is_active']
        user.is_staff = block['is_staff']
        user.is_superuser = block['is_superuser']

    def populate_user(self, user, uri, dn, conn, block):
        self.populate_user_attributes(user, uri, dn, conn, block)
        self.populate_admin_fields(user, uri, dn, conn, block)
        self.populate_mandatory_groups(user, uri, dn, conn, block)
        self.populate_user_groups(user, uri, dn, conn, block)

    def _return_user(self, uri, dn, username, password, conn, block):
        if block['transient']:
            return self._return_transient_user(uri, dn, username, password, conn, block)
        else:
            return self._return_django_user(uri, dn, username, password, conn, block)

    def _return_transient_user(self, uri, dn, username, password, conn, block):
        user = LDAPUser(block=block, dn=dn, password=password)
        self.populate_user(user, uri, dn, conn, block)
        user.pk = 'transient!{0}'.format(base64.b64encode(pickle.dumps(user)))
        return user

    def _return_django_user(self, uri, dn, username, password, conn, block):
        if block['replicas']:
            uri = block['url'][0]
        user_external_ids = UserExternalId.objects.filter(source=uri, external_id=dn)
        count = len(user_external_ids)
        if count == 0:
            log.info('creating user %r with dn %r from server %r', username, dn, uri)
            user = self.create_user(uri, dn, username, password, conn, block)
        elif count == 1:
            user = user_external_ids[0].user
            log.debug('found user %r for dn %r from server %r', user, dn, uri)
        else:
            raise NotImplementedError
        shared_cache = get_shared_cache('ldap')
        shared_cache.set('ldap-pk-{0}'.format(user.pk), (uri, dn, username,
            password, block))
        self.populate_user(user, uri, dn, conn, block)
        user.save()
        return user

    def has_usable_password(self, user):
        return True

    def get_saml2_authn_context(self):
        return lasso.SAML2_AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT
