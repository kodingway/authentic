from django.contrib import admin

from .models import (AttributeSource, UserAliasInSource,
        AttributeItem, AttributeList)

class LdapSourceAdmin(admin.ModelAdmin):
    fieldsets = (
            (None, {
                'fields' : (
                    'name',
                    'server',
                    'user',
                    'password',
                    'base',
                    'port',
                    'ldaps',
                    'certificate',
                    'is_auth_backend',
                )
            }),
    )

class AttributeListAdmin(admin.ModelAdmin):
    filter_horizontal = ('attributes', )
    fieldsets = (
            (None, {
                'fields' : (
                    'name',
                    'attributes',
                )
            }),
    )


admin.site.register(AttributeSource)
admin.site.register(UserAliasInSource)
admin.site.register(AttributeItem)
admin.site.register(AttributeList, AttributeListAdmin)

try:
    from .models import LdapSource
    admin.site.register(LdapSource, LdapSourceAdmin)
except ImportError:
    pass
