from idp.views import accumulate_from_backends

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
                links = accumulate_from_backends(self.request, 'links')
                for provider, link in links:
                    if provider.id != provider_id:
                        continue
                    d['provider'] = provider
                    d['links'].append(link)
            return d
        return super(UserFederations, self).__getattr__(name)

def federations_processor(request):
    return {'federations': UserFederations(request) }

