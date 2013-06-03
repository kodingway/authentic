from common import *

DEBUG = True

try:
    from local_settings import *
except ImportError, e:
    if 'local_settings' in e.args[0]:
        pass

if USE_DEBUG_TOOLBAR:
    try:
        import debug_toolbar
        MIDDLEWARE_CLASSES += ('debug_toolbar.middleware.DebugToolbarMiddleware',)
        INSTALLED_APPS += ('debug_toolbar',)
    except ImportError:
        print "Debug toolbar missing, not loaded"

if AUTH_SAML2:
    INSTALLED_APPS += ('authentic2.authsaml2',)
    AUTHENTICATION_BACKENDS += (
            'authentic2.authsaml2.backends.AuthSAML2PersistentBackend',
            'authentic2.authsaml2.backends.AuthSAML2TransientBackend')
    AUTH_FRONTENDS += ('authentic2.authsaml2.frontend.AuthSAML2Frontend',)
    IDP_BACKENDS += ('authentic2.authsaml2.backends.AuthSAML2Backend',)
    DISPLAY_MESSAGE_ERROR_PAGE = True

if AUTH_OPENID:
    INSTALLED_APPS += ('authentic2.auth2_auth.auth2_openid', 'django_authopenid',)
    AUTH_FRONTENDS += ('authentic2.auth2_auth.auth2_openid.backend.OpenIDFrontend',)

if AUTH_SSL:
    AUTHENTICATION_BACKENDS += ('authentic2.auth2_auth.auth2_ssl.backend.SSLBackend',)
    AUTH_FRONTENDS += ('authentic2.auth2_auth.auth2_ssl.frontend.SSLFrontend',)
    INSTALLED_APPS += ('authentic2.auth2_auth.auth2_ssl',)

if AUTH_OATH:
    INSTALLED_APPS += ('authentic2.auth2_auth.auth2_oath',)
    AUTHENTICATION_BACKENDS += ('authentic2.auth2_auth.auth2_oath.backend.OATHTOTPBackend',)
    AUTH_FRONTENDS += ('authentic2.auth2_auth.auth2_oath.frontend.OATHOTPFrontend',)

if IDP_SAML2:
    IDP_BACKENDS += ('authentic2.idp.saml.backend.SamlBackend',)

if IDP_OPENID:
    INSTALLED_APPS += ('authentic2.idp.idp_openid',)
    TEMPLATE_CONTEXT_PROCESSORS += ('authentic2.idp.idp_openid.context_processors.openid_meta',)

if IDP_CAS:
    INSTALLED_APPS += ('authentic2.idp.idp_cas',)
