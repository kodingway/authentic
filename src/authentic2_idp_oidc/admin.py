from django.contrib import admin

from . import models


class OIDCClientAdmin(admin.ModelAdmin):
    list_display = ['name', 'slug', 'client_id', 'ou', 'identifier_policy', 'created', 'modified']
    list_filter = ['ou', 'identifier_policy']
    date_hierarchy = 'modified'
    readonly_fields = ['created', 'modified']


class OIDCAuthorizationAdmin(admin.ModelAdmin):
    list_display = ['client', 'user', 'created', 'expired']
    list_filter = ['client']
    search_fields = ['user__first_name', 'user__last_name', 'user__email', 'user__username',
                     'client__name']
    date_hierarchy = 'created'
    readonly_fields = ['created', 'expired']


class OIDCCodeAdmin(admin.ModelAdmin):
    list_display = ['client', 'user', 'uuid', 'created', 'expired']
    list_filter = ['client']
    search_fields = ['user__first_name', 'user__last_name', 'user__email', 'user__username',
                     'client__name']
    date_hierarchy = 'created'
    readonly_fields = ['uuid', 'created', 'expired', 'user', 'uuid', 'client', 'state', 'nonce']


class OIDCAccessTokenAdmin(admin.ModelAdmin):
    list_display = ['client', 'user', 'uuid', 'created', 'expired']
    list_filter = ['client']
    search_fields = ['user__first_name', 'user__last_name', 'user__email', 'user__username',
                     'client__name']
    date_hierarchy = 'created'
    readonly_fields = ['uuid', 'created', 'expired']


admin.site.register(models.OIDCClient, OIDCClientAdmin)
admin.site.register(models.OIDCAuthorization, OIDCAuthorizationAdmin)
admin.site.register(models.OIDCCode, OIDCCodeAdmin)
admin.site.register(models.OIDCAccessToken, OIDCAccessTokenAdmin)
