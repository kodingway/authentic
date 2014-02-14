import base64

from . import app_settings

X509_KEYS = {
    'subject_dn': 'SSL_CLIENT_S_DN',
    'issuer_dn': 'SSL_CLIENT_I_DN',
    'serial': ('SSL_CLIENT_M_SERIAL', 'SSL_CLIENT_SERIAL'),
    'cert': 'SSL_CLIENT_CERT',
    'verify': 'SSL_CLIENT_VERIFY',
}

def normalize_cert(certificate_pem):
    '''Normalize content of the certificate'''
    base64_content = ''.join(certificate_pem.splitlines()[1:-1])
    content = base64.b64decode(base64_content)
    return base64.b64encode(content)

def explode_dn(dn):
    '''Extract sub element of a DN as displayed by mod_ssl or nginx_ssl'''
    dn = dn.strip('/')
    parts = dn.split('/')
    parts = [part.split('=') for part in parts]
    parts = [(part[0], part[1].decode('string_escape').decode('utf-8')) 
            for part in parts]
    return parts

TRANSFORM = {
        'cert': normalize_cert,
}

class SSLInfo(object):
    """
    Encapsulates the SSL environment variables in a read-only object. It
    attempts to find the ssl vars based on the type of request passed to the
    constructor. Currently only WSGIRequest and ModPythonRequest are
    supported.
    """
    def __init__(self, request):
        name = request.__class__.__name__
        if app_settings.FORCE_ENV:
            env = app_settings.FORCE_ENV
        elif name == 'WSGIRequest':
            env = request.environ
        elif name == 'ModPythonRequest':
            env = request._req.subprocess_env
        else:
            raise EnvironmentError, 'The SSL authentication currently only \
                works with mod_python or wsgi requests'
        self.read_env(env);
        pass

    def read_env(self, env):
        for attr, keys in X509_KEYS.iteritems():
            if isinstance(keys, basestring):
                keys = [keys]
            for key in keys:
                if key in env and env[key]:
                    v = env[key]
                    if attr in TRANSFORM:
                        v = TRANSFORM[attr](v)
                    self.__dict__[attr] = v
                else:
                    self.__dict__[attr] = None


        if self.__dict__['verify'] == 'SUCCESS':
            self.__dict__['verify'] = True
        else:
            self.__dict__['verify'] = False

    def get(self, attr):
        return self.__getattr__(attr)

    def __getattr__(self, attr):
        if attr in self.__dict__:
            return self.__dict__[attr]
        else:
            raise AttributeError, 'SSLInfo does not contain key %s' % attr

    def __setattr__(self, attr, value):
        raise AttributeError, 'SSL vars are read only!'

    def __repr__(self):
        return '<SSLInfo %s>' % self.__dict__
