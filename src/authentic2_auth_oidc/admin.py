from django.contrib import admin

from . import models


class OIDCClaimMappingInline(admin.TabularInline):
    model = models.OIDCClaimMapping
    fields = ['claim', 'attribute', 'verified', 'required', 'idtoken_claim', 'created', 'modified']
    readonly_fields = ['created', 'modified']


class OIDCProviderAdmin(admin.ModelAdmin):
    list_display = ['name', 'client_id', 'ou', 'created', 'modified']
    inlines = [OIDCClaimMappingInline]
    list_filter = ['ou']
    date_hierarchy = 'modified'
    readonly_fields = ['created', 'modified']


class OIDCAccountAdmin(admin.ModelAdmin):
    list_display = ['provider', 'user', 'sub', 'created', 'modified']
    search_fields = ['user__first_name', 'user__last_name', 'user__email', 'user__username']
    date_hierarchy = 'modified'
    list_filter = ['provider']
    readonly_fields = ['provider', 'user', 'sub', 'created', 'modified']

admin.site.register(models.OIDCProvider, OIDCProviderAdmin)
admin.site.register(models.OIDCAccount, OIDCAccountAdmin)
