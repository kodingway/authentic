from authentic2.decorators import setting_enabled

from . import app_settings

def openid_enabled(func):
    return setting_enabled('ENABLE', app_settings)(func)

