import ldap
import ldap.modlist
import logging
import random

# code copied from http://www.amherst.k12.oh.us/django-ldap.html

log = logging.getLogger(__name__)

from django.conf import settings
from django.contrib.auth.models import Group
try:
    import lasso
except ImportError:
    pass


from authentic2.compat import get_user_model


class LDAPBackendError(Exception):
    pass


_DEFAULTS = {
    'binddn': None,
    'bindpw': None,
    'user_dn_template': None,
    'user_filter': 'uid={username}',
    'group_dn_template': None,
    'group_filter': '(&(member={user_dn})(objectClass=groupOfNames))',
    'group': None,
    'groupsu': None,
    'groupstaff': None,
    'groupactive': None,
    'replicas': True,
    'email_field': 'mail',
    'fname_field': 'givenName',
    'lname_field': 'sn',
    'timeout': 1,
    'disable_update': False,
    'use_for_data' : None,
    'bind_with_username': False,
}

_REQUIRED = ('url', 'basedn')
_TO_ITERABLE = ('url', 'groupsu', 'groupstaff', 'groupactive')

def log_exception(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except:
            log.exception('exception in authenticate')
            raise
    return wrapper

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

    @log_exception
    def authenticate(self, username=None, password=None):
        if username is None or password is None:
            log.debug('Username or password is None, automatically returning None')
            return None

        blocks = self.get_blocks()
        # First get our configuration into a standard format
        for block in blocks:
            for r in _REQUIRED:
                if r not in block:
                    raise LDAPBackendError('Missing required configuration option: %s' % r)

            for d in _DEFAULTS:
                if d not in block:
                    block[d] = _DEFAULTS[d]

            for i in _TO_ITERABLE:
                if isinstance(block[i], basestring):
                    block[i] = (block[i],)

            # Want to randomize our access, otherwise what's the point of having multiple servers?
            block['url'] = list(block['url'])
            random.shuffle(block['url'])

        # Now we can try to authenticate
        for block in blocks:
            user = self.authenticate_block(block, username, password)
            if user is not None:
                break
        if user is None:
            log.info('User %s could not be authenticated' % username)
        return user

    def authenticate_block(self, block, username, password):
        log.debug('Processing block, settings: %s' % str(block))
        for opt in ('NETWORK_TIMEOUT', 'TIMELIMIT', 'TIMEOUT'):
            ldap.set_option(getattr(ldap, 'OPT_%s' % opt), block['timeout'])


        for uri in block['url']:
            log.debug('Attempting to authenticate to %s' % uri)
            conn = ldap.initialize(uri)

            if not conn:
                log.error('Could not initialize connection to %s' % uri)
                continue

            try:
                if block['user_dn_template']:
                    dn = block['user_dn_template'].format(username=username)
                else:
                    # if necessary bind as admin
                    if block['binddn'] is not None:
                        try:
                            conn.simple_bind_s(block['binddn'], block['bindpw'])
                        except ldap.INVALID_CREDENTIALS:
                            log.error('%s returned invalid credentials for admin user %s' % (uri, block['binddn']))
                            if block['replicas']:
                                return None
                            continue
                        except ldap.LDAPError:
                            log.exception('unable to do an admin bind on %s', uri)
                            if block['replicas']:
                                return None
                            continue
                    try:
                        if block.get('bind_with_username'):
                            results = [[username]]
                        else:
                            user_basedn = block.get('user_basedn', block['basedn'])
                            query = block['user_filter'].format(username=username)
                            log.debug('using query %r from base dn %r', query, user_basedn)
                            results = conn.search_s(user_basedn, ldap.SCOPE_SUBTREE, query)
                    except ldap.NO_SUCH_OBJECT:
                        log.error('user basedn %s not found', user_basedn)
                        if block['replicas']:
                            return None
                        continue
                    except ldap.LDAPError:
                        log.exception('unable to lookup user %r', username)
                        if block['replicas']:
                            return None
                        continue
                    if len(results) == 0:
                        log.debug('user %r not found on server %s', username, uri)
                        return None
                    elif len(results) > 1:
                        log.debug('user %r returned too much records on server %s', username, uri)
                        return None
                    dn = results[0][0]
                try:
                    conn.simple_bind_s(dn, password)
                except ldap.INVALID_CREDENTIALS:
                    log.debug('%s returned invalid credentials' % uri)
                    if block['replicas']:
                        return None
                    continue
                except ldap.LDAPError, e:
                    log.error('Got error from LDAP library: %s' % str(e))
                    return None
                return self._return_user(uri, dn, username, password, conn, block)
            finally:
                del conn
        return None

    def get_user(self, user_id):
        try:
            return get_user_model().objects.get(pk=user_id)
        except get_user_model().DoesNotExist:
            return None

    def _parse_simple_config(self):
        if len(settings.LDAP_AUTH_SETTINGS) < 2:
            raise LDAPBackendError('In a minimal configuration, you must at least specify url and user DN')
        return {'url': settings.LDAP_AUTH_SETTINGS[0], 'basedn': settings.LDAP_AUTH_SETTINGS[1]}

    def backend_name(self):
        return '%s.%s' % (__name__, self.__class__.__name__)

    def _return_user(self, uri, dn, username, password, conn, block):
        try:
            user = get_user_model().objects.get(username=username)
        except get_user_model().DoesNotExist:
            log.info('User %s did not exist in Django database, creating' % username)
            user = get_user_model()(username=username, password='')
            user.set_unusable_password()
        backend_id = '%s!%s' % (uri, dn)
        if user.backend != self.backend_name() or user.backend_id != backend_id:
            user.backend = self.backend_name()
            user.backend_id = backend_id

        log.debug('Getting information for %s from LDAP' % username)
        try:
            results = conn.search_s(dn, ldap.SCOPE_BASE, '(objectclass=*)',
                    [block['email_field'], block['fname_field'],
                        block['lname_field']])
        except ldap.LDAPError, e:
            log.warning('Could not get user information for %r, returning possibly stale user object' % username)
            user.save()
            return user
        if len(results) > 1:
            log.warning('Too much records returned for user %r on %s, not updating attributes.', username, uri)
            return user
        results = results[0][1]
        ldap_data = {}
        if block['email_field'] is not None:
            ldap_data['email'] =  results[block['email_field']][0] if block['email_field'] in results else ''
        if block['fname_field'] is not None:
            ldap_data['first_name'] = results[block['fname_field']][0] if block['fname_field'] in results else ''
        if block['lname_field'] is not None:
            ldap_data['last_name'] = results[block['lname_field']][0] if block['lname_field'] in results else ''

        if block['binddn'] is not None:
            try:
                conn.simple_bind_s(block['binddn'], block['bindpw'])
            except ldap.INVALID_CREDENTIALS:
                log.error('%s returned invalid credentials for %s' % (uri, block['binddn']))
                if block['replicas'] is True:
                    raise LDAPBackendError('unable to bind')
                return user
        group_basedn = block.get('group_basedn', block['basedn'])
        try:
            results = conn.search_s(group_basedn, ldap.SCOPE_SUBTREE,
                    block['group_filter'].format(user_dn=dn), ['cn'])
        except ldap.NO_SUCH_OBJECT:
            results = []
        groups_cn = filter(None, (result[1].get('cn', [None])[0] for result in results))
        log.info('found groups %s for user %r', groups_cn, username)
        for g, attr in (('groupsu', 'is_superuser'), ('groupstaff', 'is_staff'), ('groupactive', 'is_active')):
            if block[g] is None:
                continue
            ldap_data[attr] = False
            for group in block[g]:
                if group in groups_cn:
                    ldap_data[attr] = True
                    break
        for key in ldap_data:
            if isinstance(ldap_data[key], basestring):
                ldap_data[key] = ldap_data[key].decode('utf-8')
        log.debug(str(ldap_data))
        log.info('Data for user %s has changed, updating Django database' % username)
        log.debug('Setting attributes: %s' % str(ldap_data))
        for attr in ldap_data:
            setattr(user, attr, ldap_data[attr])
        user.save()
        if block.get('group_mapping'):
            mapping = block['group_mapping']
            for cn, django_groups in mapping.iteritems():
                add = cn in groups_cn
                for django_group in django_groups:
                    group, created = Group.objects.get_or_create(name=django_group)
                    if add:
                        user.groups.add(group)
                    else:
                        user.groups.remove(group)
        if block.get('set_mandatory_groups'):
            django_groups = block['set_mandatory_groups']
            for django_group in django_groups:
                if not django_group:
                    continue
                group, created = Group.objects.get_or_create(name=django_group)
                user.groups.add(group)
        return user

    def has_usable_password(self, user):
        return True

    def get_user_connection(self, user):
        blocks = self.get_blocks()
        url, dn = user.backend_id.split('!', 1)
        for block in blocks:
            if url in block['url']:
                break
        else:
            raise RuntimeError('Cannot find the backend for user %s' % user)
        conn = ldap.initialize(url)
        try:
            conn.simple_bind_s(block['binddn'], block['bindpw'])
        except ldap.LDAPError, e:
            log.error('Error during rebind: %s' % str(e))
            raise
        return conn, block

    def set_password(self, user, raw_password):
        conn, block = self.get_user_connection(user)
        url, dn = user.backend_id.split('!', 1)
        results = conn.search_s(dn, ldap.SCOPE_BASE)
        new_entry = results[0][1].copy()
        new_entry['userPassword'] = [ raw_password.encode('utf-8') ]
        conn.modify_s(dn, ldap.modlist.modifyModlist(
            results[0][1], new_entry))
        log.debug('Changed password of %s to %r' % (user, raw_password))

    def check_password(self, user, raw_password):
        conn, block = self.get_user_connection(user)
        url, dn = user.backend_id.split('!', 1)
        log.debug('Checking password of %s to %r' % (user, raw_password))
        try:
            conn.simple_bind_s(dn, raw_password)
            user.password = raw_password
            return True
        except ldap.LDAPError:
            return False

    def save(self, user, *args, **kwargs):
        conn, block = self.get_user_connection(user)
        url, dn = user.backend_id.split('!', 1)
        if 'use_for_data' in block:
            results = conn.search_s(dn, ldap.SCOPE_BASE)
            new_entry = results[0][1].copy()
            fields = (
                    ('email_field', 'email'),
                    ('fname_field', 'first_name'),
                    ('lname_field', 'last_name'))
            for field, attribute in fields:
                ldap_attribute = block.get(field)
                if ldap_attribute is None:
                    continue
                content = getattr(user, attribute, None)
                if content:
                    new_entry[ldap_attribute] = [ content.encode('utf-8') ]
                else:
                    new_entry.pop(ldap_attribute, None)
            log.debug('Change attribute of %s to %r' % (user, new_entry))
            conn.modify_s(dn, ldap.modlist.modifyModlist(results[0][1], new_entry))
        return False

    def get_saml2_authn_context(self, request):
        ssl = 'HTTPS' in request.environ
        if ssl:
            return lasso.SAML2_AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT
        else:
            return lasso.SAML2_AUTHN_CONTEXT_PASSWORD

# LDAP_AUTH_SETTINGS = ('ldap://10.0.44.2', 'cn=users,dc=example,dc=com')
#
# LDAP_AUTH_SETTINGS = ('ldap://10.0.44.2', 'cn=users,dc=example,dc=com', 'django_login',
#   'cn=groups,dc=example,dc=com')
#
# LDAP_AUTH_SETTINGS = (('ldap://10.0.44.2', 'ldaps://10.0.44.200'), 'cn=users,dc=example,dc=com',
#   ('django_login', 'staff', 'web_users'), 'cn=groups,dc=example,dc=com')
#
# -*> means required
# --> means optional
# LDAP_AUTH_SETTINGS = (
#   {'url': ('ldap://10.0.44.2', 'ldaps://10.0.44.200'),    -*> can be string or iterable of strings
#       'userdn': 'cn=users,dc=example,dc=com',             -*> ldap subtree in which users are stored
#       'binddn': 'diradmin',                             --> admin name if users are not allowed to search
#       'bindpw': 'supersecret',                            --> password for binddn
#       'group': ('django_users', 'web_users', 'staff'),    --> can be None, string, or iterable of group names
#                                                               if set, user must be in one of these groups
#                                                               also, must set groupdn
#       'groupdn': 'cn=groups,dc=example,dc=com',           --> ldap subtree in which groups are stored
#       'groupsu': ('wheel', 'admin', 'django_superusers'), --> can be None, string or iterable of group names
#                                                               if set, users in these groups will be Django
#                                                               "superusers"
#       'groupstaff': ('staff', 'django_staff'),            --> can be None, string or iterable of group names
#                                                               if set, users in these groups will be Django
#                                                               "staff"
#       'groupactive': 'active_users',                      --> can be None, string or iterable of group names
#                                                               if set, users in these groups will be "active"
#                                                               in Django
#                                                               users not in any group will be "inactive" in
#                                                               Django
#       'replicas': False,                                  --> If True, will stop querying this block's
#                                                               servers on the first response, positive or
#                                                               negative.  If False, it will try to authenticate
#                                                               against each server before moving onto the next
#                                                               block
#       'use_for_data': True,                               --> If True, the Django User object first_name,
#                                                               last_name, and email fields will be taken from
#                                                               LDAP.  See *_field settings.
#       'email_field': 'mail',                              --> The LDAP attribute of the person object that
#                                                               holds the user's email address
#       'fname_field': 'givenName',                         --> The LDAP attribute of the person object that
#                                                               holds the user's first name
#       'lname_field': 'sn'                                 --> The LDAP attribute of the person object that
#                                                               holds the user's last name
#       'attribute_map': {
#           'givenName': 'first_name',
#           'sn': 'last_name',
#           'mail': 'email',
#       }
#       }
#   # Can repeat with totally different set of authentication servers/settings
#   # Useful for a situation where you have multiple masters with multiple replicas that are all possibly
#   # valid authentication points
# )
