from django.utils.translation import ugettext_lazy as _

from admin_tools.dashboard import modules


def get_admin_modules():
    '''Show Client model in authentic2 admin'''
    model_list = modules.ModelList(_('Authentic2 Plugin Template'),
            models=('authentic2_plugin_template.models.*',))
    return (model_list,)

