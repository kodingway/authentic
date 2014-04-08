"""
This file was generated with the customdashboard management command, it
contains the two classes for the main dashboard and app index dashboard.
You can customize these classes as you want.

To activate your index dashboard add the following to your settings.py::
    ADMIN_TOOLS_INDEX_DASHBOARD = 'authentic2.dashboard.CustomIndexDashboard'

And to activate the app index dashboard::
    ADMIN_TOOLS_APP_INDEX_DASHBOARD = 'authentic2.dashboard.CustomAppIndexDashboard'
"""

from django.conf import settings
from django.utils.translation import ugettext_lazy as _
from django.core.urlresolvers import reverse

from admin_tools.dashboard import modules, Dashboard, AppIndexDashboard
from admin_tools.utils import get_admin_site_name

from . import plugins, compat

class CustomIndexDashboard(Dashboard):
    """
    Custom index dashboard for authentic2.
    """
    def init_with_context(self, context):
        site_name = get_admin_site_name(context)
        # append a link list module for "quick links"
        self.children.append(modules.LinkList(
            _('Quick links'),
            layout='inline',
            draggable=False,
            deletable=False,
            collapsible=False,
            children=[
                [_('Return to site'), '/'],
                [_('Change password'),
                 reverse('%s:password_change' % site_name)],
                [_('Log out'), reverse('%s:logout' % site_name)],
            ]
        ))

        # append an app list module for "Applications"
        User = compat.get_user_model()
        user_class = '{0}.{1}'.format(User.__module__, User.__name__)
        self.children.append(modules.ModelList(
            _('Users and groups'),
            models=(user_class,
                'django.contrib.auth.models.*',
                'authentic2.models.Attribute'),
        ))
        self.children.append(modules.ModelList(
            _('SAML2'),
            models=(
                'authentic2.saml.models.LibertyProvider',
                'authentic2.saml.models.SPOptionsIdPPolicy',
                'authentic2.saml.models.IdPOptionsSPPolicy',
                'authentic2.idp.models.AttributePolicy',
                'authentic2.attribute_aggregator.models.AttributeList',
                'authentic2.attribute_aggregator.models.AttributeItem',
                'authentic2.attribute_aggregator.models.AttributeSource',
            ),
        ))
        self.children.append(modules.ModelList(
            _('Debug'),
            models=(
                'authentic2.models.AttributeValue',
                'authentic2.nonce.models.Nonce',
                'authentic2.models.FederatedId',
                'authentic2.models.LogoutUrl',
                'authentic2.models.AuthenticationEvent',
                'authentic2.models.UserExternalId',
                'authentic2.models.DeletedUser',
                'django.contrib.sessions.*',
            ),
        ))
        for plugin in plugins.get_plugins():
            if hasattr(plugin, 'get_admin_modules') and callable(plugin.get_admin_modules):
                plugin_modules = plugin.get_admin_modules()
                for module in plugin_modules:
                    self.children.append(module)

        # append a recent actions module
        self.children.append(modules.RecentActions(_('Recent Actions'), 5))

        # append another link list module for "support".
        self.children.append(modules.LinkList(
            _('Support'),
            children=[
                {
                    'title': _('Authentic2 documentation'),
                    'url': 'http://pythonhosted.org/authentic2/',
                    'external': True,
                },
                {
                    'title': _('Authentic2 project'),
                    'url': 'http://dev.entrouvert.org/projects/authentic/',
                    'external': True,
                },
                {
                    'title': _('Authentic Mailing List'),
                    'url': 'http://listes.entrouvert.com/info/authentic',
                    'external': True,
                },
            ]
        ))


class CustomAppIndexDashboard(AppIndexDashboard):
    """
    Custom app index dashboard for authentic2.
    """

    # we disable title because its redundant with the model list module
    title = ''

    def __init__(self, *args, **kwargs):
        AppIndexDashboard.__init__(self, *args, **kwargs)

        # append a model list module and a recent actions module
        self.children += [
            modules.ModelList(self.app_title, self.models),
            modules.RecentActions(
                _('Recent Actions'),
                include_list=self.get_app_content_types(),
                limit=5
            )
        ]

    def init_with_context(self, context):
        """
        Use this method if you need to access the request context.
        """
        return super(CustomAppIndexDashboard, self).init_with_context(context)
