import logging

from collections import defaultdict
from idp.views import accumulate_from_backends

class UserFederations(object):
    '''Provide access to all federations of the current user'''
    def __init__(self, request):
        self.request = request

    def links(self):
        links = accumulate_from_backends(self.request, 'links')
        logging.debug('federations: %s', links)
        d = defaultdict(lambda:[])
        for key, value in links:
            d[key.replace('-','_')].append(value)
        return d

def federations_processor(request):
    return {'federations': UserFederations(request) }

