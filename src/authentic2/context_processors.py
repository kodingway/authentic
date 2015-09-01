from collections import defaultdict

from pkg_resources import get_distribution
from django.conf import settings

from . import utils, app_settings, constants

class UserFederations(object):
    '''Provide access to all federations of the current user'''
    def __init__(self, request):
        self.request = request

    def __getattr__(self, name):
        d = { 'provider': None, 'links': [] }
        if name.startswith('service_'):
            try:
                provider_id = int(name.split('_', 1)[1])
            except ValueError:
                pass
            else:
                links = utils.accumulate_from_backends(self.request, 'links')
                for provider, link in links:
                    if provider.id != provider_id:
                        continue
                    d['provider'] = provider
                    d['links'].append(link)
            return d
        return super(UserFederations, self).__getattr__(name)

__AUTHENTIC2_DISTRIBUTION = None

def a2_processor(request):
    global __AUTHENTIC2_DISTRIBUTION
    variables = {}
    variables.update(app_settings.TEMPLATE_VARS)
    variables['federations'] = UserFederations(request)
    if __AUTHENTIC2_DISTRIBUTION is None:
        if settings.DEBUG:
            __AUTHENTIC2_DISTRIBUTION = repr(get_distribution('authentic2'))
        else:
            __AUTHENTIC2_DISTRIBUTION = str(get_distribution('authentic2'))
    variables['AUTHENTIC2_VERSION'] = __AUTHENTIC2_DISTRIBUTION
    variables['add_to_blocks'] = defaultdict(lambda:[])
    variables['LAST_LOGIN'] = request.session.get(constants.LAST_LOGIN_SESSION_KEY)
    variables['USER_SWITCHED'] = constants.SWITCH_USER_SESSION_KEY in request.session
    return variables
