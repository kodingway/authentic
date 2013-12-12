from django.conf import settings

from django.conf.urls import patterns, url

from authentic2.authsaml2.saml2_endpoints import metadata, sso, finish_federation, \
    singleSignOnArtifact, singleSignOnPost, sp_slo, singleLogoutReturn, \
    singleLogoutSOAP, singleLogout, federationTermination, manageNameIdReturn, \
    manageNameIdSOAP, manageNameId, delete_federation, redirect_to_disco, \
    disco_response, finish_slo

urlpatterns = patterns('',
    (r'^metadata$', metadata),
    # Receive request from user interface
    (r'^sso$', sso),
    (r'^finish_federation$', finish_federation),
    (r'^singleSignOnArtifact$', singleSignOnArtifact),
    (r'^singleSignOnPost$', singleSignOnPost),
    # Receive request from functions
    (r'^sp_slo/(.*)$', sp_slo),
    # Receive response from Redirect SP initiated
    (r'^singleLogoutReturn$', singleLogoutReturn),
    # Receive request from SOAP IdP initiated
    (r'^singleLogoutSOAP$', singleLogoutSOAP),
    # Receive request from Redirect IdP initiated
    (r'^singleLogout$', singleLogout),
    # Back of SLO treatment by the IdP Side
    (r'^finish_slo$', finish_slo),
    # Receive request from user interface
    (r'^federationTermination$', federationTermination),
    # Receive response from Redirect SP initiated
    (r'^manageNameIdReturn$', manageNameIdReturn),
    # Receive request from SOAP IdP initiated
    (r'^manageNameIdSOAP$', manageNameIdSOAP),
    # Receive request from Redirect IdP initiated
    (r'^manageNameId$', manageNameId),
    # Receive request from Redirect IdP initiated
    url(r'^delete_federation/$', delete_federation,
        name='authsaml2-delete-federation'),
)

try:
    if settings.USE_DISCO_SERVICE:
        urlpatterns += patterns('',
            #Send idp discovery request
            (r'^redirect_to_disco$', redirect_to_disco),
            #receive idp discovery response
            (r'^discoveryReturn$', disco_response),
        )
except:
    pass
