import logging
import sys
from StringIO import StringIO
import re

from ldap.dn import escape_dn_chars
from ldif import LDIFWriter


from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from optparse import make_option

COMMAND = 1
ATTR = 2

MAPPING = {
    'uuid': 'uid',
    'username': 'cn',
    'first_name': 'givenName',
    'last_name': 'sn',
    'email': 'mail',
}

def unescape_filter_chars(s):
    return re.sub(r'\\..', lambda s: s.group()[1:].decode('hex'), s)

class Command(BaseCommand):
    help = 'OpenLDAP shell backend'


    def ldap(self, command, attrs):
        self.logger.debug('received command %s %s', command, attrs)
        if command == 'SEARCH':
            out = StringIO()
            ldif_writer = LDIFWriter(out)
            qs = get_user_model().objects.all()
            if attrs['filter'] != '(objectClass=*)':
                m = re.match(r'\((\w*)=(.*)\)', attrs['filter'])
                if not m:
                    print 'RESULT'
                    print 'code: 1'
                    print 'info: invalid filter'
                    print
                    return
                for user_attribute, ldap_attribute in MAPPING.iteritems():
                    if ldap_attribute == m.group(1):
                        break
                else:
                    print 'RESULT'
                    print 'code: 1'
                    print 'info: unknown attribute in filter'
                    print
                    return
                value = m.group(2)
                if value.endswith('*') and value.startswith('*'):
                    user_attribute += '__icontains'
                    value = value[1:-1]
                elif value.endswith('*'):
                    user_attribute += '__istartswith'
                    value = value[:-1]
                elif value.startswith('*'):
                    user_attribute += '__iendswith'
                    value = value[1:]
                else:
                    user_attribute += '__iexact'
                value = unescape_filter_chars(value)
                qs = qs.filter(**{user_attribute: value.decode('utf-8')})
            for user in qs:
                o = {}
                for user_attribute, ldap_attribute in MAPPING.iteritems():
                    o[ldap_attribute] = [unicode(getattr(user, user_attribute)).encode('utf-8')]
                o['objectClass'] = ['inetOrgPerson']
                dn = 'uid=%s,%s' % (escape_dn_chars(o['uid'][0]), attrs['suffix'])
                self.logger.debug(u'sending entry %s %s', dn, o)
                ldif_writer.unparse(dn, o)
            print out.getvalue(),
            out.close()
        print 'RESULT'
        print 'code: 0'
        print 'info: RockNRoll'
        print

    def handle(self, *args, **options):
        self.logger = logging.getLogger(__name__)
        state = COMMAND
        attrs = {}
        while True:
            line = sys.stdin.readline()
            if not line:
                break
            if state == COMMAND:
                command = line.strip()
                state = ATTR
            elif state == ATTR:
                if line == '\n':
                    self.ldap(command, attrs)
                    state == COMMAND
                    attrs = {}
                    sys.stdout.flush()
                    sys.exit(0)
                else:
                    key, value = line.strip().split(':')
                    attrs[key] = value[1:]
