from django.conf import settings

from . import utils

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

def a2_processor(request):
    variables = {}
    variables.update(getattr(settings, 'TEMPLATE_VARS', {}))
    variables['federations'] = UserFederations(request)
    return variables
