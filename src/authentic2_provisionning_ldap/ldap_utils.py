import socket
import time
import tempfile
import shutil
import subprocess
import os
import ldap
import ldap.modlist
from ldap.ldapobject import ReconnectLDAPObject
import ldap.sasl
from ldap.controls import SimplePagedResultsControl
import ldif
import StringIO


SLAPD_PATH = None
SLAPADD_PATH = None
SLAPD_PATHS = ['/bin', '/usr/bin', '/sbin', '/usr/sbin', '/usr/local/bin', '/usr/local/sbin']


def has_slapd():
    global SLAPD_PATH, SLAPADD_PATH, PATHS
    if not SLAPD_PATH or not SLAPADD_PATH:
        for path in SLAPD_PATHS:
            slapd_path = os.path.join(path, 'slapd')
            if os.path.exists(slapd_path):
                SLAPD_PATH = slapd_path
            slapadd_path = os.path.join(path, 'slapadd')
            if os.path.exists(slapd_path):
                SLAPADD_PATH = slapadd_path
    return not (SLAPD_PATH is None or SLAPADD_PATH is None)

class ListLDIFParser(ldif.LDIFParser):
    def __init__(self, *args, **kwargs):
        self.entries = []
        ldif.LDIFParser.__init__(self, *args, **kwargs)

    def handle(self, dn, entry):
        self.entries.append((dn, entry))

    def add(self, conn):
        for dn, entry in self.entries:
            conn.add_s(dn, ldap.modlist.addModlist(entry))

class Slapd(object):
    '''Initiliaze an OpenLDAP server with just one database containing branch
       o=orga and loading the core schema. ACL are very permissive.
    '''
    config_ldif = '''dn: cn=config
objectClass: olcGlobal
cn: config
olcToolThreads: 1
olcLogLevel: none

dn: cn=module{{0}},cn=config
objectClass: olcModuleList
cn: module{{0}}
olcModulePath: /usr/lib/ldap
olcModuleLoad: {{0}}back_hdb
olcModuleLoad: {{1}}back_monitor
olcModuleLoad: {{2}}back_mdb
olcModuleLoad: {{3}}accesslog
olcModuleLoad: {{4}}unique
olcModuleLoad: {{5}}refint
olcModuleLoad: {{6}}constraint
olcModuleLoad: {{7}}syncprov

dn: cn=schema,cn=config
objectClass: olcSchemaConfig
cn: schema

dn: olcDatabase={{-1}}frontend,cn=config
objectClass: olcDatabaseConfig
objectClass: olcFrontendConfig
olcDatabase: {{-1}}frontend
olcAccess: {{0}}to *
   by dn.exact=gidNumber={gid}+uidNumber={uid},cn=peercred,cn=external,cn=auth manage
   by * break
olcAccess: {{1}}to dn.exact="" by * read
olcAccess: {{2}}to dn.base="cn=Subschema" by * read
olcSizeLimit: unlimited
olcTimeLimit: unlimited

dn: olcDatabase={{0}}config,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {{0}}config
olcRootDN: uid=admin,cn=config
olcRootPW: admin
olcAccess: {{0}}to *
   by dn.exact=gidNumber={gid}+uidNumber={uid},cn=peercred,cn=external,cn=auth manage
   by * break
'''
    first_db_ldif = '''dn: olcDatabase={{1}}mdb,cn=config
objectClass: olcDatabaseConfig
objectClass: olcMdbConfig
olcDatabase: {{1}}mdb
olcSuffix: o=orga
olcDbDirectory: {path}
olcRootDN: uid=admin,o=orga
olcRootPW: admin
olcReadOnly: FALSE
# Index
olcAccess: {{0}}to * by manage

dn: o=orga
objectClass: organization
o: orga
'''
    process = None
    data_dir_name = 'data'
    schemas_ldif = [
            open(os.path.join(os.path.dirname(__file__), 'tests', 'core.ldif')).read(),
            open(os.path.join(os.path.dirname(__file__), 'tests', 'cosine.ldif')).read(),
            open(os.path.join(os.path.dirname(__file__), 'tests', 'inetorgperson.ldif')).read(),
            open(os.path.join(os.path.dirname(__file__), 'tests', 'nis.ldif')).read(),
    ]

    def create_process(self, args):
        return subprocess.Popen(args, stdin=subprocess.PIPE,
                env=os.environ, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def __init__(self, **kwargs):
        assert has_slapd()
        self.__dict__.update(kwargs)
        self.checkpoints = []
        self.slapd_dir = tempfile.mkdtemp(prefix='a2-provision-slapd')
        self.config_dir = os.path.join(self.slapd_dir, 'slapd.d')
        os.mkdir(self.config_dir)
        self.data_dir = os.path.join(self.slapd_dir, self.data_dir_name)
        os.mkdir(self.data_dir)
        self.socket = os.path.join(self.slapd_dir, 'socket')
        self.ldapi_url = 'ldapi://%s' % self.socket.replace('/', '%2F')
        self.slapadd(self.config_ldif)
        for schema_ldif in self.schemas_ldif:
            self.slapadd(schema_ldif, do_format=False)
        self.start()
        self.add_ldif(self.first_db_ldif, do_format=True)

    def slapadd(self, ldif, do_format=True):
        if do_format:
            ldif = ldif.format(path=self.data_dir, gid=os.getgid(), uid=os.getuid())
        slapadd = self.create_process([SLAPADD_PATH, '-v', '-n0', '-F', self.config_dir])
        stdout, stderr = slapadd.communicate(input=ldif)
        assert slapadd.returncode == 0, 'slapadd failed: %s' % stderr

    def start(self):
        '''Launch slapd'''
        if self.process and self.process.returncode is None:
            self.stop()
        cmd = [SLAPD_PATH,
                '-d0', # put slapd in foreground
                '-F' + self.config_dir,
                '-h', self.ldapi_url]
        self.process = self.create_process(cmd)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        # Detect slapd listening
        while True:
            try:
                sock.connect(self.socket)
            except socket.error:
                # Yield so that slapd has time to initialize
                time.sleep(0)
            else:
                break

    def stop(self):
        '''Send SIGTERM to slapd'''
        if self.process:
            self.process.terminate()
            self.process.wait()
            self.process = None

    def checkpoint(self):
        '''Stop slapd and save current data state'''
        self.checkpoints.append(os.path.join(self.slapd_dir, 'checkpoint-%d' % len(self.checkpoints)))
        self.stop()
        shutil.copytree(self.data_dir, self.checkpoints[-1])
        self.start()

    def restore(self):
        '''Stop slapd and restore last data state'''
        assert self.checkpoints, 'no checkpoint exists'
        self.stop()
        shutil.rmtree(self.data_dir)
        shutil.copytree(self.checkpoints[-1], self.data_dir)
        shutil.rmtree(self.checkpoints[-1])
        self.checkpoints.pop()
        self.start()

    # Clean behind us
    def __del__(self):
        self.clean()

    def clean(self):
        '''Remove directory'''
        if self.slapd_dir:
            if os.path.exists(self.slapd_dir):
                self.stop()
                shutil.rmtree(self.slapd_dir, ignore_errors=True)
                self.slapd_dir = None

    def __enter__(self):
        return self

    def __exit__(self, type, value, tb):
        self.clean()

    def add_ldif(self, ldif, do_format=False):
        if do_format:
            ldif = ldif.format(path=self.data_dir, gid=os.getgid(), uid=os.getuid())
        parser = ListLDIFParser(StringIO.StringIO(ldif))
        parser.parse()
        conn = self.get_connection()
        conn.simple_bind_s('uid=admin,cn=config', 'admin')
        parser.add(conn)

    def get_connection(self):
        return ldap.initialize(self.ldapi_url)

class PagedResultsSearchObject:
  page_size = 500

  def paged_search_ext_s(self,base,scope,filterstr='(objectClass=*)',attrlist=None,attrsonly=0,serverctrls=None,clientctrls=None,timeout=-1,sizelimit=0):
    """
    Behaves exactly like LDAPObject.search_ext_s() but internally uses the
    simple paged results control to retrieve search results in chunks.

    This is non-sense for really large results sets which you would like
    to process one-by-one
    """

    while True: # loop for reconnecting if necessary

      req_ctrl = SimplePagedResultsControl(True,size=self.page_size,cookie='')

      try:

        # Send first search request
        msgid = self.search_ext(
          base,
          scope,
          filterstr=filterstr,
          attrlist=attrlist,
          attrsonly=attrsonly,
          serverctrls=(serverctrls or [])+[req_ctrl],
          clientctrls=clientctrls,
          timeout=timeout,
          sizelimit=sizelimit
        )

        all_results = []

        while True:
          rtype, rdata, rmsgid, rctrls = self.result3(msgid)
          for result in rdata:
              yield result
          all_results.extend(rdata)
          # Extract the simple paged results response control
          pctrls = [
            c
            for c in rctrls
            if c.controlType == SimplePagedResultsControl.controlType
          ]
          if pctrls:
            if pctrls[0].cookie:
                # Copy cookie from response control to request control
                req_ctrl.cookie = pctrls[0].cookie
                msgid = self.search_ext(
                  base,
                  scope,
                  filterstr=filterstr,
                  attrlist=attrlist,
                  attrsonly=attrsonly,
                  serverctrls=(serverctrls or [])+[req_ctrl],
                  clientctrls=clientctrls,
                  timeout=timeout,
                  sizelimit=sizelimit
                )
            else:
              break # no more pages available

      except ldap.SERVER_DOWN:
        self.reconnect(self._uri)
      else:
        break


class PagedLDAPObject(ReconnectLDAPObject,PagedResultsSearchObject):
  pass

if __name__ == '__main__':
    with Slapd() as slapd:
        conn = slapd.get_connection()
        conn.simple_bind_s('uid=admin,o=orga', 'admin')
        assert conn.whoami_s() == 'dn:uid=admin,o=orga'
        slapd.checkpoint()
        slapd.add_ldif('''dn: uid=admin,o=orga
objectClass: person
objectClass: uidObject
uid: admin
cn: admin
sn: admin
''')
        conn = slapd.get_connection()
        print conn.search_s('o=orga', ldap.SCOPE_SUBTREE)
        slapd.restore()
        conn = slapd.get_connection()
        print conn.search_s('o=orga', ldap.SCOPE_SUBTREE)

