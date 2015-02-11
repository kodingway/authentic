from django.contrib import admin

from .models import AttributePolicy

class AttributePolicyAdmin(admin.ModelAdmin):
    filter_horizontal = ('source_filter_for_sso_from_push_sources', )
    fieldsets = (
            (None, {
                'fields' : (
                    'name',
                    'enabled',
                    'ask_consent_attributes',
                    'allow_attributes_selection',
                    'attribute_list_for_sso_from_pull_sources',
                    'forward_attributes_from_push_sources',
                    'map_attributes_from_push_sources',
                    'output_name_format',
                    'output_namespace',
                    'source_filter_for_sso_from_push_sources',
                    'attribute_filter_for_sso_from_push_sources',
                    'filter_source_of_filtered_attributes',
                    'map_attributes_of_filtered_attributes',
                    'send_error_and_no_attrs_if_missing_required_attrs',
                )
            }),
    )



admin.site.register(AttributePolicy, AttributePolicyAdmin)
