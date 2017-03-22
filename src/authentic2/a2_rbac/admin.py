from django.contrib import admin
from django.utils.translation import ugettext_lazy as _

from . import models


class RoleParentInline(admin.TabularInline):
    model = models.RoleParenting
    fk_name = 'child'
    fields = ['parent']

    def get_queryset(self, request):
        return super(RoleParentInline, self).get_queryset(request) \
            .filter(direct=True)


class RoleChildInline(admin.TabularInline):
    model = models.RoleParenting
    fk_name = 'parent'
    fields = ['child']

    def get_queryset(self, request):
        return super(RoleChildInline, self).get_queryset(request) \
            .filter(direct=True)


class RoleAttributeInline(admin.TabularInline):
    model = models.RoleAttribute


class RoleAdmin(admin.ModelAdmin):
    inlines = [RoleChildInline, RoleParentInline]
    fields = ('uuid', 'name', 'slug', 'description', 'ou', 'members',
              'permissions', 'admin_scope_ct', 'admin_scope_id', 'service')
    readonly_fields = ('uuid',)
    prepopulated_fields = {"slug": ("name",)}
    filter_horizontal = ('members', 'permissions')
    list_display = ('__unicode__', 'slug', 'ou', 'service', 'admin_scope')
    list_select_related = True
    list_filter = ['ou', 'service']
    inlines = [RoleAttributeInline]


class OrganizationalUnitAdmin(admin.ModelAdmin):
    fields = ('uuid', 'name', 'slug', 'description', 'username_is_unique',
              'email_is_unique', 'default')
    readonly_fields = ('uuid',)
    prepopulated_fields = {"slug": ("name",)}
    list_display = ('name', 'slug')


class PermissionAdmin(admin.ModelAdmin):
    fields = ('operation', 'ou', 'target_ct', 'target_id')
    list_display = ('name', 'operation', 'ou', 'target')
    list_select_related = True

    def name(self, obj):
        return unicode(obj)
    name.short_description = _('name')

admin.site.register(models.Role, RoleAdmin)
admin.site.register(models.OrganizationalUnit, OrganizationalUnitAdmin)
admin.site.register(models.Permission, PermissionAdmin)
