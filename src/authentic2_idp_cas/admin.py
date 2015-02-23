from django import forms
from django.contrib import admin
from django.utils.translation import ugettext as _
# Django < 1.7 compat
from authentic2.attributes_ng.engine import get_attribute_names
from authentic2.decorators import to_iter
from authentic2.admin import CleanupAdminMixin

from . import models

class ServiceForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super(ServiceForm, self).__init__(*args, **kwargs)
        choices = self.choices({'user': None, 'request': None})
        self.fields['identifier_attribute'].choices = choices
        self.fields['identifier_attribute'].widget = forms.Select(choices=choices)

    @to_iter
    def choices(self, ctx):
        return [('', _('None'))] + get_attribute_names(ctx)

    class Meta:
        model = models.Service

class AttributeInlineForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super(AttributeInlineForm, self).__init__(*args, **kwargs)
        choices = self.choices({'user': None, 'request': None})
        self.fields['attribute_name'].choices = choices
        self.fields['attribute_name'].widget = forms.Select(choices=choices)

    @to_iter
    def choices(self, ctx):
        return [('', _('None'))] + get_attribute_names(ctx)

    class Meta:
        model = models.Attribute
        fields = [
                'slug',
                'attribute_name',
                'enabled',
        ]

class AttributeInlineAdmin(admin.TabularInline):
    model = models.Attribute
    form = AttributeInlineForm

class ServiceAdmin(admin.ModelAdmin):
    form = ServiceForm
    list_display = ('name', 'slug', 'urls', 'identifier_attribute')
    prepopulated_fields = {"slug": ("name",)}
    fieldsets = (
            (None, {
                'fields': [
                    'name',
                    'slug',
                    'urls',
                    'identifier_attribute',
                ]
             }),
            (_('Logout'), {
                'fields': [
                    'logout_url',
                    'logout_use_iframe',
                    'logout_use_iframe_timeout',
                ],
             }))
    inlines = [AttributeInlineAdmin]

class TicketAdmin(CleanupAdminMixin, admin.ModelAdmin):
    list_display = (
            'ticket_id',
            'validity',
            'renew',
            'service',
            'service_url',
            'user',
            'identifier',
            'creation',
            'expire'
    )

admin.site.register(models.Service, ServiceAdmin)

admin.site.register(models.Ticket, TicketAdmin)
