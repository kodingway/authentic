from copy import deepcopy

from django.contrib import admin
from django.conf import settings
from django.utils.translation import ugettext_lazy as _
from django.contrib.auth.admin import GroupAdmin, UserAdmin
from django.contrib.auth.models import Group

from .nonce.models import Nonce
from . import forms, models, admin_forms, compat, app_settings

if settings.DEBUG:
    class NonceModelAdmin(admin.ModelAdmin):
        list_display = ("value", "context", "not_on_or_after")
    admin.site.register(Nonce, NonceModelAdmin)
    class AttributeValueAdmin(admin.ModelAdmin):
        list_display = ('content_type', 'owner', 'attribute',
                'content')
    admin.site.register(models.AttributeValue, AttributeValueAdmin)
    admin.site.register(models.FederatedId)
    admin.site.register(models.LogoutUrl)
    admin.site.register(models.AuthenticationEvent)
    admin.site.register(models.UserExternalId)

class UserRealmListFilter(admin.SimpleListFilter):
    # Human-readable title which will be displayed in the
    # right admin sidebar just above the filter options.
    title = _('realm')

    # Parameter for the filter that will be used in the URL query.
    parameter_name = 'realm'

    def lookups(self, request, model_admin):
        """
        Returns a list of tuples. The first element in each
        tuple is the coded value for the option that will
        appear in the URL query. The second element is the
        human-readable name for the option that will appear
        in the right sidebar.
        """
        return app_settings.REALMS

    def queryset(self, request, queryset):
        """
        Returns the filtered queryset based on the value
        provided in the query string and retrievable via
        `self.value()`.
        """
        if self.value():
            return queryset.filter(username__endswith=u'@' + self.value())
        return queryset

class AuthenticUserAdmin(UserAdmin):
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        (_('Personal info'), {'fields': ('first_name', 'last_name',)}),
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
    list_filter = UserAdmin.list_filter + (UserRealmListFilter,)

    def get_fieldsets(self, request, obj=None):
        fieldsets = deepcopy(super(AuthenticUserAdmin, self).get_fieldsets(request, obj))
        if obj:
            if not request.user.is_superuser:
                fieldsets[2][1]['fields'] = filter(lambda x: x !=
                        'is_superuser', fieldsets[2][1]['fields'])
            qs = models.Attribute.objects.all()
            insertion_idx = 2
        else:
            qs = models.Attribute.objects.filter(required=True)
            insertion_idx = 1
        if qs.exists():
            fieldsets = list(fieldsets)
            fieldsets.insert(insertion_idx, 
                    (_('Attributes'), {'fields': [at.name for at in qs]}))
        return fieldsets

User = compat.get_user_model()
if User.__module__ == 'django.contrib.auth.models':
    if User in admin.site._registry:
        admin.site.unregister(User)
    admin.site.register(User, AuthenticUserAdmin)

class AttributeAdmin(admin.ModelAdmin):
    list_display = ('label', 'kind', 'required',
            'asked_on_registration', 'user_editable',
            'user_visible')

admin.site.register(models.Attribute, AttributeAdmin)


class A2GroupAdmin(GroupAdmin):
    form = forms.GroupAdminForm


admin.site.unregister(Group)
admin.site.register(Group, A2GroupAdmin)
