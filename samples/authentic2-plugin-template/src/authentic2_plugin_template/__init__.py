__version__ = '1.0.0'

class Plugin(object):
    def get_before_urls(self):
        from . import urls
        return urls.urlpatterns

    def get_after_urls(self):
        return []

    def get_apps(self):
        return [__name__]

    def get_before_middleware(self):
        return []

    def get_after_middleware(self):
        return []

    def get_authentication_backends(self):
        return []

    def get_auth_frontends(self):
        return []

    def get_idp_backends(self):
        return []

    def get_admin_modules(self):
        from . import dashboard
        return dashboard.get_admin_modules()

    def service_list(self, request):
        '''For IdP plugins this method add links to the user homepage.
           
           It must return a list of authentic2.utils.Service objects, each
           object has a name and can have an url and some actions.

                Service(name=name[, url=url[, actions=actions]])

           Actions are a list of tuples, whose parts are
           - first the name of the action,
           - the HTTP method for calling the action,
           - the URL for calling the action,
           - the paramters to pass to this URL as a sequence of key-value tuples.
        '''
        return []

    def logout_list(self, request):
        '''For IdP or SP plugins this method add actions to logout from remote
           IdP or SP.
           
           It must returns a list of HTML fragments, each fragment is
           responsible for calling the view doing the logout. Views are usually
           called using <img/> or <iframge/> tags and finally redirect to an
           icon indicating success or failure for the logout.

           Authentic2 provide two such icons through the following URLs:
           - os.path.join(settings.STATIC_URL, 'authentic2/img/ok.png')
           - os.path.join(settings.STATIC_URL, 'authentic2/img/ok.png')
           '''
        return []
