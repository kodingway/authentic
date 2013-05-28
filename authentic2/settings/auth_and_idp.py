from django.conf import settings


if settings.USE_DEBUG_TOOLBAR:
    try:
        import debug_toolbar
        settings.MIDDLEWARE_CLASSES += ('debug_toolbar.middleware.DebugToolbarMiddleware',)
        settings.INSTALLED_APPS += ('debug_toolbar',)
    except ImportError:
        print "Debug toolbar missing, not loaded"

if settings.AUTH_SAML2:
    settings.INSTALLED_APPS += ('authentic2.authsaml2',)
    settings.AUTHENTICATION_BACKENDS += (
            'authentic2.authsaml2.backends.AuthSAML2PersistentBackend',
            'authentic2.authsaml2.backends.AuthSAML2TransientBackend')
    settings.AUTH_FRONTENDS += ('authentic2.authsaml2.frontend.AuthSAML2Frontend',)
    settings.IDP_BACKENDS += ('authentic2.authsaml2.backends.AuthSAML2Backend',)
    settings.DISPLAY_MESSAGE_ERROR_PAGE = True

if settings.AUTH_OPENID:
    settings.INSTALLED_APPS += ('authentic2.auth2_auth.auth2_openid', 'django_authopenid',)
    settings.AUTH_FRONTENDS += ('authentic2.auth2_auth.auth2_openid.backend.OpenIDFrontend',)

if settings.AUTH_SSL:
    settings.AUTHENTICATION_BACKENDS += ('authentic2.auth2_auth.auth2_ssl.backend.SSLBackend',)
    settings.AUTH_FRONTENDS += ('authentic2.auth2_auth.auth2_ssl.frontend.SSLFrontend',)
    settings.INSTALLED_APPS += ('authentic2.auth2_auth.auth2_ssl',)

if settings.AUTH_OATH:
    settings.INSTALLED_APPS += ('authentic2.auth2_auth.auth2_oath',)
    settings.AUTHENTICATION_BACKENDS += ('authentic2.auth2_auth.auth2_oath.backend.OATHTOTPBackend',)
    settings.AUTH_FRONTENDS += ('authentic2.auth2_auth.auth2_oath.frontend.OATHOTPFrontend',)

if settings.IDP_SAML2:
    settings.IDP_BACKENDS += ('authentic2.idp.saml.backend.SamlBackend',)

if settings.IDP_OPENID:
    settings.INSTALLED_APPS += ('authentic2.idp.idp_openid',)
    settings.TEMPLATE_CONTEXT_PROCESSORS += ('authentic2.idp.idp_openid.context_processors.openid_meta',)

if settings.IDP_CAS:
    settings.INSTALLED_APPS += ('authentic2.idp.idp_cas',)
