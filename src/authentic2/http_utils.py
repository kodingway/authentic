
import requests

from authentic2 import app_settings

def get_url(url):
    '''Does a simple GET on an URL, check the certificate'''
    verify = app_settings.A2_VERIFY_SSL
    if verify and app_settings.CAFILE:
        verify = app_settings.CAFILE
    return requests.get(url, verify=verify).text
