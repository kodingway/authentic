from copy import deepcopy
import pprint

from django.contrib import admin
from django.conf import settings
from django.utils.translation import ugettext_lazy as _
from django.contrib.auth.admin import GroupAdmin, UserAdmin
from django.contrib.auth.models import Group
from django.contrib.sessions.models import Session

from .nonce.models import Nonce
from . import forms, models, admin_forms, compat, app_settings

class NonceModelAdmin(admin.ModelAdmin):
    list_display = ("value", "context", "not_on_or_after")
admin.site.register(Nonce, NonceModelAdmin)
class AttributeValueAdmin(admin.ModelAdmin):
    list_display = ('content_type', 'owner', 'attribute',
            'content')
admin.site.register(models.AttributeValue, AttributeValueAdmin)
class FederatedIdAdmin(admin.ModelAdmin):
    list_display = ('provider', 'about', 'service', 'id_format', 'id_value')
    list_filter = ('provider', 'about', 'service', 'id_format')

admin.site.register(models.FederatedId, FederatedIdAdmin)
class LogoutUrlAdmin(admin.ModelAdmin):
    list_display = ('provider', 'logout_url', 'logout_use_iframe', 'logout_use_iframe_timeout')
admin.site.register(models.LogoutUrl, LogoutUrlAdmin)
class AuthenticationEventAdmin(admin.ModelAdmin):
    list_display = ('when', 'who', 'how', 'nonce')
    list_filter = ('how',)
    date_hierarchy = 'when'
    search_fields = ('who', 'nonce', 'how')

admin.site.register(models.AuthenticationEvent, AuthenticationEventAdmin)
class UserExternalIdAdmin(admin.ModelAdmin):
    list_display = ('user', 'source', 'external_id', 'created', 'updated')
    list_filter = ('source',)
    date_hierarchy = 'created'
    search_fields = ('user__username', 'source', 'external_id')
admin.site.register(models.UserExternalId, UserExternalIdAdmin)
class DeletedUserAdmin(admin.ModelAdmin):
    list_display = ('user', 'creation')
    date_hierarchy = 'creation'
admin.site.register(models.DeletedUser, DeletedUserAdmin)

DB_SESSION_ENGINES = (
    'django.contrib.sessions.backends.db',
    'django.contrib.sessions.backends.cached_db',
)

if settings.SESSION_ENGINE in DB_SESSION_ENGINES:
    class SessionAdmin(admin.ModelAdmin):
        def _session_data(self, obj):
            return pprint.pformat(obj.get_decoded()).replace('\n', '<br>\n')
        _session_data.allow_tags = True
        _session_data.short_description = _('session data')
        list_display = ['session_key', 'ips', 'user', '_session_data', 'expire_date']
        fields = ['session_key', 'ips', 'user', '_session_data', 'expire_date']
        readonly_fields = ['ips', 'user', '_session_data']
        date_hierarchy = 'expire_date'

        def ips(self, session):
            content = session.get_decoded()
            ips = content.get('ips', set())
            return ', '.join(ips)
        ips.short_description = _('IP adresses')

        def user(self, session):
            from django.contrib import auth
            from django.contrib.auth import models as auth_models
            content = session.get_decoded()
            user_id = content[auth.SESSION_KEY]
            backend_class = content[auth.BACKEND_SESSION_KEY]
            backend = auth.load_backend(backend_class)
            try:
                user = backend.get_user(user_id) or auth_models.AnonymousUser()
            except:
                user = '<failure>'
            return user
        user.short_description = _('user')


    admin.site.register(Session, SessionAdmin)

class ExternalUserListFilter(admin.SimpleListFilter):
    title = _('external')

    parameter_name = 'external'

    def lookups(self, request, model_admin):
        return (
                ('1', _('Yes')),
                ('0', _('No'))
        )

    def queryset(self, request, queryset):
        """
        Returns the filtered queryset based on the value
        provided in the query string and retrievable via
        `self.value()`.
        """
        if self.value() == '1':
            return queryset.filter(userexternalid__isnull=False)
        elif self.value() == '0':
            return queryset.filter(userexternalid__isnull=True)
        return queryset

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
    list_filter = UserAdmin.list_filter + (UserRealmListFilter,ExternalUserListFilter)

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
