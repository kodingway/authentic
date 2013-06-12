"""
This file was generated with the customdashboard management command, it
contains the two classes for the main dashboard and app index dashboard.
You can customize these classes as you want.

To activate your index dashboard add the following to your settings.py::
    ADMIN_TOOLS_INDEX_DASHBOARD = 'authentic2.dashboard.CustomIndexDashboard'

And to activate the app index dashboard::
    ADMIN_TOOLS_APP_INDEX_DASHBOARD = 'authentic2.dashboard.CustomAppIndexDashboard'
"""

from django.utils.translation import ugettext_lazy as _
from django.core.urlresolvers import reverse

from admin_tools.dashboard import modules, Dashboard, AppIndexDashboard
from admin_tools.utils import get_admin_site_name


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
        self.children.append(modules.ModelList(
            _('User and groups'),
            models=('authentic2.models.User',
                'django.contrib.auth.models.Group'),
        ))
        self.children.append(modules.ModelList(
            _('Services'),
            models=(
                'authentic2.saml.models.LibertyProvider',
                'authentic2.saml.models.SPOptionsIdPPolicy',
                'authentic2.saml.models.IdPOptionsSPPolicy',
                'authentic2.idp.models.AttributeList',
                'authentic2.idp.models.AttributeItem',
                'authentic2.idp.models.AttributePolicy',
                'authentic2.attribute_aggregator.models.AttributeSource',
            ),
        ))

        # append a recent actions module
        self.children.append(modules.RecentActions(_('Recent Actions'), 5))

        # append a feed module
        self.children.append(modules.Feed(
            _('Latest Authentic News'),
            feed_url='http://dev.entrouvert.org/projects/authentic/news.atom',
            limit=5
        ))

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
                    'url': 'https://lists.labs.libre-entreprise.org/mailman/listinfo/authentic-devel/',
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
