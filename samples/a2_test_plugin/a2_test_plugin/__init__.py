class Plugin(object):
    def get_before_urls(self):
        from . import urls
        return urls.urlpatterns

    def get_apps(self):
        return [__name__]
