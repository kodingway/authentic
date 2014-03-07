from copy import deepcopy

from django.contrib import admin
from django.conf import settings
from django.utils.translation import ugettext_lazy as _
from django.contrib.auth.admin import GroupAdmin
from django.contrib.auth.models import Group

from .nonce.models import Nonce
from . import forms

if settings.DEBUG:
    class NonceModelAdmin(admin.ModelAdmin):
        list_display = ("value", "context", "not_on_or_after")
    admin.site.register(Nonce, NonceModelAdmin)

if settings.AUTH_USER_MODEL == 'authentic2.User':
    import models
    import admin_forms

    from django.contrib.auth.admin import UserAdmin
    class AuthenticUserAdmin(UserAdmin):
        fieldsets = (
            (None, {'fields': ('username', 'password')}),
            (_('Personal info'), {'fields': ('first_name', 'last_name',
                'email', 'nickname', 'url', 'company', 'phone',
                'postal_address')}),
            (_('Permissions'), {'fields': ('is_active', 'is_staff', 'is_superuser',
                                           'groups')}),
            (_('Important dates'), {'fields': ('last_login', 'date_joined')}),
        )
        form = admin_forms.UserChangeForm
        add_form = admin_forms.UserCreationForm
        add_fieldsets = (
                (None, {
                    'classes': ('wide',),
                    'fields': ('username', 'first_name', 'last_name', 'email', 'password1', 'password2')}
                ),
            )

        def get_fieldsets(self, request, obj=None):
            fieldsets = deepcopy(super(AuthenticUserAdmin, self).get_fieldsets(request, obj))
            if obj:
                if not request.user.is_superuser:
                    fieldsets[2][1]['fields'] = filter(lambda x: x !=
                            'is_superuser', fieldsets[2][1]['fields'])
            return fieldsets


    admin.site.register(models.User, AuthenticUserAdmin)

class A2GroupAdmin(GroupAdmin):
    form = forms.GroupAdminForm


admin.site.unregister(Group)
admin.site.register(Group, A2GroupAdmin)
