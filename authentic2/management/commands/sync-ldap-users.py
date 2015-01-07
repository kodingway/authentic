try:
    import ldap
    from ldap.filter import filter_format
except ImportError:
    ldap = None

from django.core.management.base import BaseCommand, CommandError

from authentic2.backends.ldap_backend import LDAPBackend

class Command(BaseCommand):

    def handle(self, *args, **kwargs):
        for user in LDAPBackend.get_users():
            user.save()
