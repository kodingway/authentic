from django.template.loader import render_to_string
from django.utils.translation import ugettext_lazy as _

from .constants import SESSION_CAS_LOGOUTS

__version__ = '1.0'

class Plugin(object):
    def get_before_urls(self):
        from . import app_settings
        from django.conf.urls import patterns, include
        from authentic2.decorators import setting_enabled, required

        return required(
                (
                    setting_enabled('ENABLE', settings=app_settings),
                ),
                patterns('',
                    (r'^idp/cas/', include(__name__ + '.urls'))))

    def get_apps(self):
        return [__name__]

    def logout_list(self, request):
        fragments = []
        cas_logouts = request.session.get(SESSION_CAS_LOGOUTS, [])
        for name, url, use_iframe, use_iframe_timeout in cas_logouts:
            ctx = {
                'needs_iframe': use_iframe,
                'name': name,
                'url': url,
                'iframe_timeout': use_iframe_timeout,
            }
            content = render_to_string('authentic2_idp_cas/logout_fragment.html', ctx)
            fragments.append(content)
        return fragments

    def get_admin_modules(self):
        from admin_tools.dashboard import modules
        return [modules.ModelList(
            _('CAS'),
            models=(
                '%s.*' % __name__,
            ),
        )]
