import ldap
import ldap.modlist
import logging
import random

# code copied from http://www.amherst.k12.oh.us/django-ldap.html

log = logging.getLogger(__name__)

from django.conf import settings
from django.contrib.auth import get_user_model


class LDAPBackendError(Exception):
    pass


_DEFAULTS = {
    'bindname': None,
    'bindpw': None,
    'group': None,
    'groupdn': None,
    'groupsu': None,
    'groupstaff': None,
    'groupactive': None,
    'replicas': True,
    'email_field': 'mail',
    'fname_field': 'givenName',
    'lname_field': 'sn',
    'timeout': 1,
    'disable_update': False
}

_REQUIRED = ('url', 'userdn')
_TO_ITERABLE = ('url', 'group', 'groupsu', 'groupstaff', 'groupactive')

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
                if isinstance(block[i], str):
                    block[i] = (block[i],)

            # Want to randomize our access, otherwise what's the point of having multiple servers?
            block['url'] = list(block['url'])
            random.shuffle(block['url'])

        # Now we can try to authenticate
        for block in blocks:
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
                    try:
                        dn = 'uid=%s,%s' % (username, block['userdn'])
                        conn.simple_bind_s(dn, password)

                    except ldap.INVALID_CREDENTIALS:
                        log.debug('%s returned invalid credentials' % uri)
                        if block['replicas'] is True:
                            return None
                        break

                    except ldap.LDAPError, e:
                        log.error('Got error from LDAP library: %s' % str(e))
                        break

                    if block['group'] is None:
                        log.info('%s authenticated successfully against %s' % (username, uri))
                        return self._return_user(uri, dn, username, password, conn, block)

                    # If your directory is setup such that this user couldn't search (for whatever reason)
                    # switch to an account that can so we can check the group
                    if block['bindname'] is not None:
                        log.debug('Rebinding to check group membership')
                        conn.unbind()
                        del conn
                        conn = ldap.initialize(uri)
                        try:
                            conn.simple_bind_s('uid=%s,%s' % (block['bindname'], block['userdn']), block['bindpw'])
                        except ldap.LDAPError, e:
                            log.error('Error during rebind: %s' % str(e))
                            break

                    for group in block['group']:
                        log.debug('Checking if %s is a member of %s' % (username, group))
                        result = conn.search_s('cn=%s,%s' % (group, block['groupdn']), ldap.SCOPE_SUBTREE,
                            '(objectclass=*)', ['memberuid'])

                        # If there's more than one result, it gets ignored (there shouldn't be more than one
                        # group with the same name anyway)
                        if not result:
                            log.debug('No group found with name %s' % group)
                            continue
                        if 'memberUid' not in result[0][1]:
                            log.debug('No memberUid in group %s' % group)
                            continue

                        result = result[0][1]['memberUid']
                        if username in result:
                            log.info('%s authenticated successfully against %s' % (username, uri))
                            return self._return_user(uri, dn, username, password, conn, block)

                    if block['replicas'] is True:
                        break
                finally:
                    del conn

        log.info('User %s could not be authenticated' % username)
        return None


    def get_user(self, user_id):
        try:
            return get_user_model().objects.get(pk=user_id)
        except get_user_model().DoesNotExist:
            return None


    def _parse_simple_config(self):
        if len(settings.LDAP_AUTH_SETTINGS) < 2:
            raise LDAPBackendError('In a minimal configuration, you must at least specify url and user DN')
        ret = {'url': settings.LDAP_AUTH_SETTINGS[0], 'userdn': settings.LDAP_AUTH_SETTINGS[1]}

        if len(settings.LDAP_AUTH_SETTINGS) < 3:
            return ret

        if len(settings.LDAP_AUTH_SETTINGS) < 4:
            raise LDAPBackendError('If you specify a required group, you must specify the group DN as well')
        ret['group'] = settings.LDAP_AUTH_SETTINGS[2]
        ret['groupdn'] = settings.LDAP_AUTH_SETTINGS[3]
        return ret

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

        if block['disable_update']:
            user.save()
            return user

        for p in ('fname_field', 'lname_field', 'email_field', 'groupsu', 'groupstaff', 'groupactive'):
            if block[p] is not None:
                break
        else:
            user.save()
            return user

        log.debug('Getting information for %s from LDAP' % username)
        results = conn.search_s('uid=%s,%s' % (username, block['userdn']), ldap.SCOPE_BASE,
            '(objectclass=*)', [block['email_field'], block['fname_field'], block['lname_field']])
        if not results:
            log.warning('Could not get user information for %s, returning possibly stale user object' % username)
            user.save()
            return user
        results = results[0][1]

        ldap_data = {}
        if block['email_field'] is not None:
            ldap_data['email'] =  results[block['email_field']][0] if block['email_field'] in results else ''
        if block['fname_field'] is not None:
            ldap_data['first_name'] = results[block['fname_field']][0] if block['fname_field'] in results else ''
        if block['lname_field'] is not None:
            ldap_data['last_name'] = results[block['lname_field']][0] if block['lname_field'] in results else ''

        for g, attr in (('groupsu', 'is_superuser'), ('groupstaff', 'is_staff'), ('groupactive', 'is_active')):
            if block[g] is not None:
                ldap_data[attr] = False
                for group in block[g]:
                    result = conn.search_s('cn=%s,%s' % (group, block['groupdn']), ldap.SCOPE_SUBTREE,
                        '(objectclass=*)', ['member'])

                    if not result or 'member' not in result[0][1]:
                        continue

                    result = result[0][1]['member']
                    if dn in result:
                        ldap_data[attr] = True
                        break
        log.debug(str(ldap_data))
        for attr in ldap_data:
            if getattr(user, attr) != ldap_data[attr]:
                break
        else:
            user.save()
            return user

        log.info('Data for user %s has changed, updating Django database' % username)
        log.debug('Setting attributes: %s' % str(ldap_data))
        for attr in ldap_data:
            setattr(user, attr, ldap_data[attr])
        user.save()
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
            conn.simple_bind_s('uid=%s,%s' % (block['bindname'], block['userdn']), block['bindpw'])
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
        if block['use_for_data']:
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
#       'bindname': 'diradmin',                             --> admin name if users are not allowed to search
#       'bindpw': 'supersecret',                            --> password for bindname
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
