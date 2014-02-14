# -*- coding: utf-8 -*-

import sys


class AppSettings(object):
    '''Thanks django-allauth'''
    __DEFAULTS = dict(
            FORCE_ENV={},
            ACCEPT_SELF_SIGNED=False,
            STRICT_MATCH=False,
            SUBJECT_MATCH_KEYS=(),
            CREATE_USERNAME_CALLBACK=None,
            USE_COOKIE=False,
            CREATE_USER=False,
    )

    def __init__(self, prefix):
        self.prefix = prefix

    @property
    def settings(self):
        from django.conf import settings
        return settings

    def __getattr__(self, key):
        if key in self.__DEFAULTS:
            return getattr(self.settings,
                    self.prefix+key, self.__DEFAULTS[key])
        else:
            from django.core.exceptions import ImproperlyConfigured
            try:
                return getattr(self.settings, self.prefix+key)
            except AttributeError:
                raise ImproperlyConfigured('settings %s is missing' % self.prefix+key)


app_settings = AppSettings('SSLAUTH_')
app_settings.__name__ = __name__
app_settings.__file__ = __file__
sys.modules[__name__] = app_settings
