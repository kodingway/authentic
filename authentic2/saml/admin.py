import urllib2
import logging

from django.contrib import admin
from django.utils.translation import ugettext as _
from django.conf import settings
from django.forms import ModelForm
import django.forms
from django.contrib import messages

from authentic2.saml.models import LibertyProvider, LibertyServiceProvider
from authentic2.saml.models import LibertyIdentityProvider, IdPOptionsSPPolicy
from authentic2.saml.models import SPOptionsIdPPolicy
from authentic2.saml.models import LibertyProviderPolicy
from authentic2.saml.models import LibertySessionDump, LibertyFederation
from authentic2.saml.models import LibertyAssertion, LibertySessionSP, KeyValue
from authentic2.saml.models import LibertySession
from authentic2.http_utils import get_url

logger = logging.getLogger(__name__)

class AuthorizationAttributeMapAdmin(admin.ModelAdmin):
    fieldsets = (
            (None, {
                'fields' : (
                    'name',
                )
            }),
    )

class AuthorizationAttributeMappingAdmin(admin.ModelAdmin):
    fieldsets = (
            (None, {
                'fields' : (
                    'attribute_name',
                    'attribute_value',
                    'map',
                )
            }),
    )

class IdPOptionsSPPolicyAdmin(admin.ModelAdmin):
    fieldsets = (
            (None, {
                'fields' : (
                    'name',
                    'enabled',
                    'no_nameid_policy',
                    'requested_name_id_format',
                    'transient_is_persistent',
                    'allow_create',
                    ('enable_binding_for_sso_response',
                        'binding_for_sso_response'),
                    ('enable_http_method_for_slo_request',
                        'http_method_for_slo_request'),
                    ('enable_http_method_for_defederation_request',
                        'http_method_for_defederation_request'),
                    'force_user_consent',
                    'want_force_authn_request',
                    'want_is_passive_authn_request',
                    'want_authn_request_signed',
                    'handle_persistent',
                    'handle_transient',
                    'back_url',
                    'accept_slo',
                    'forward_slo',
                )
            }),
    )

class AuthorizationSPPolicyAdmin(admin.ModelAdmin):
    fieldsets = (
            (None, {
                'fields' : (
                    'name',
                    'enabled',
                    'attribute_map',
                    'default_denial_message',
                )
            }),
    )

class LibertyServiceProviderInline(admin.StackedInline):
    model = LibertyServiceProvider

class LibertyIdentityProviderInline(admin.StackedInline):
    model = LibertyIdentityProvider
    fieldsets = (
            (None, {
                'fields' : (
                    'enabled',
                    'enable_following_idp_options_policy',
                    'idp_options_policy',
#                    'enable_following_authorization_policy',
#                    'authorization_policy',
                )
            }),
    )

class TextAndFileWidget(django.forms.widgets.MultiWidget):
    def __init__(self, attrs=None):
        widgets = (django.forms.widgets.Textarea(),
                django.forms.widgets.FileInput(),)
        super(TextAndFileWidget, self).__init__(widgets, attrs)

    def decompress(self, value):
        return (value, None)

    def value_from_datadict(self, data, files, name):
        # If there is a file input use it
        file = self.widgets[1].value_from_datadict(data, files, name + '_1')
        if file:
            file = file.read(file.size)
        if file:
            value = file
        else:
            value = self.widgets[0].value_from_datadict(data, files, name + '_0')
        return value

    def render(self, name, value, attrs=None):
        if attrs is None:
            attrs = {}
        if isinstance(value, (str, unicode)):
            attrs['rows'] = value.count('\n') + 5
            attrs['cols'] = min(max((len(x) for x in value.split('\n'))), 150)
        return super(TextAndFileWidget, self).render(name, value, attrs)


class LibertyProviderForm(ModelForm):
    metadata = django.forms.CharField(required=True,widget=TextAndFileWidget)
    public_key = django.forms.CharField(required=False,widget=TextAndFileWidget)
    ssl_certificate = django.forms.CharField(required=False,widget=TextAndFileWidget)
    ca_cert_chain = django.forms.CharField(required=False,widget=TextAndFileWidget)
    class Meta:
        model = LibertyProvider

def update_metadata(modeladmin, request, queryset):
    updated = []
    for provider in queryset:
        if provider.entity_id.startswith('http'):
            try:
                data = get_url(provider.entity_id)
                if data != provider.metadata:
                    provider.metadata = data
                    updated.append(provider.entity_id)
                    provider.save()
            except (urllib2.URLError, IOError), e:
                messages.error(request, _('Failure to resolve %s: %s') %
                        (provider.entity_id, e))
    if updated:
        updated = ', '.join(updated)
        messages.info(request, _('Metadata update for: %s') % updated)

class LibertyProviderAdmin(admin.ModelAdmin):
    form = LibertyProviderForm
    list_display = ('name', 'entity_id', 'protocol_conformance')
    list_display_links = ('entity_id',)
    list_editable = ('name',)
    search_fields = ('name', 'entity_id')
    readonly_fields = ('entity_id','protocol_conformance','entity_id_sha1','federation_source')
    fieldsets = (
            (None, {
                'fields' : ('name', 'entity_id', 'entity_id_sha1','federation_source')
            }),
            (_('Metadata files'), {
                'fields': ('metadata', 'public_key', 'ssl_certificate', 'ca_cert_chain')
            }),
    )
    inlines = [
            LibertyServiceProviderInline,
            LibertyIdentityProviderInline
    ]
    actions = [ update_metadata ]


class LibertyProviderPolicyAdmin(admin.ModelAdmin):
    inlines = [
            LibertyServiceProviderInline,
    ]

class LibertyFederationAdmin(admin.ModelAdmin):
    search_fields = ('name_id_content', 'user__username')
    list_display = ('user', 'creation', 'last_modification', 'name_id_content', 'format', 'idp', 'sp')
    list_filter = ('name_id_format', 'idp', 'sp')

    def format(self, obj):
        name_id_format = obj.name_id_format
        if name_id_format > 15:
            name_id_format = u'\u2026' + name_id_format[-12:]
        return name_id_format

admin.site.register(IdPOptionsSPPolicy, IdPOptionsSPPolicyAdmin)
admin.site.register(SPOptionsIdPPolicy)
admin.site.register(LibertyProvider, LibertyProviderAdmin)
admin.site.register(LibertyProviderPolicy, LibertyProviderPolicyAdmin)

if settings.DEBUG:
    admin.site.register(LibertySessionDump)
    admin.site.register(LibertyFederation, LibertyFederationAdmin)
    admin.site.register(LibertySession)
    admin.site.register(LibertyAssertion)
    admin.site.register(LibertySessionSP)
    admin.site.register(KeyValue)
