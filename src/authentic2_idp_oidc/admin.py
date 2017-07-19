from django.contrib import admin

from . import models


class OIDCClientAdmin(admin.ModelAdmin):
    list_display = ['name', 'slug', 'client_id', 'ou', 'identifier_policy', 'created', 'modified']
    list_filter = ['ou', 'identifier_policy']
    date_hierarchy = 'modified'
    readonly_fields = ['created', 'modified']


class OIDCAuthorizationAdmin(admin.ModelAdmin):
    list_display = ['client', 'user', 'created', 'expired']
    search_fields = ['user__first_name', 'user__last_name', 'user__email', 'user__username']
    date_hierarchy = 'created'
    readonly_fields = ['created', 'expired']

    def get_queryset(self, request):
        qs = super(OIDCAuthorizationAdmin, self).get_queryset(request)
        qs = qs.prefetch_related('client')
        return qs

    def get_search_results(self, request, queryset, search_term):
            from django.contrib.contenttypes.models import ContentType
            from authentic2.a2_rbac.models import OrganizationalUnit as OU

            queryset, use_distinct = super(OIDCAuthorizationAdmin, self).get_search_results(
                request, queryset, search_term)
            clients = models.OIDCClient.objects.filter(name__contains=search_term).values_list('pk')
            ous = OU.objects.filter(name__contains=search_term).values_list('pk')
            queryset |= self.model.objects.filter(
                client_ct=ContentType.objects.get_for_model(models.OIDCClient),
                client_id=clients)
            queryset |= self.model.objects.filter(
                client_ct=ContentType.objects.get_for_model(OU),
                client_id=ous)
            return queryset, use_distinct


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
