import cStringIO
import urllib2

pycurl = None
try:
    import pycurl
except ImportError:
    pass
M2Crypto = None
try:
    import M2Crypto
except ImportError:
    pass

from authentic2 import app_settings

def get_url_pycurl(url):
    '''Use pycurl to retrieve an HTTPS URL, preferred to M2Crypto as it also
       handles Server Name Indication (SNI).
    '''
    try:
        buf = cStringIO.StringIO()
        c = pycurl.Curl()
        c.setopt(c.URL, str(url))
        c.setopt(c.WRITEFUNCTION, buf.write)
        c.setopt(pycurl.CAINFO, app_settings.CAFILE)
        c.setopt(pycurl.CAPATH, app_settings.CAPATH)
        if app_settings.A2_VERIFY_SSL:
            c.setopt(pycurl.SSL_VERIFYHOST, 2)
            c.setopt(pycurl.SSL_VERIFYPEER, 1)
        else:
            c.setopt(pycurl.SSL_VERIFYHOST, 0)
            c.setopt(pycurl.SSL_VERIFYPEER, 0)
        c.perform()
        r = buf.getvalue()
        buf.close()
        http_code = c.getinfo(pycurl.HTTP_CODE)
        if http_code != 200:
            raise urllib2.HTTPError(url, http_code, None, None, None)
        return r
    except pycurl.error, e:
        # Wrap error
        raise urllib2.URLError('SSL access error %s' % e)

__M2CRYPTO_SSL_CONTEXT = None

def get_m2crypto_ssl_context():
    '''Create an SSL Context and cache it in global __M2CRYPTO_SSL_CONTEXT'''
    global __M2CRYPTO_SSL_CONTEXT

    if __M2CRYPTO_SSL_CONTEXT is None:
        __M2CRYPTO_SSL_CONTEXT = M2Crypto.SSL.Context()
        __M2CRYPTO_SSL_CONTEXT.load_verify_locations(cafile=app_settings.CAFILE, 
                capath=app_settings.CAPATH)
    return __M2CRYPTO_SSL_CONTEXT

def get_url_m2crypto(url):
    '''Use M2Crypto to retrieve an HTTPs URL'''
    try:
        return M2Crypto.m2urllib2.build_opener(get_m2crypto_ssl_context()).open(url).read()
    except M2Crypto.SSL.Checker.SSLVerificationError, e:
        # Wrap error
        raise urllib2.URLError('SSL Verification error %s' % e)

def get_url(url):
    '''Does a simple GET on an URL, if the URL uses TLS, M2Crypto is used to
       check the certificate'''

    if url.startswith('https'):
        if pycurl:
            return get_url_pycurl(url)
        if M2Crypto:
            return get_url_m2crypto(url)
        raise urllib2.URLError('https is unsupported without either pyCurl or M2Crypto')
    return urllib2.urlopen(url).read()
