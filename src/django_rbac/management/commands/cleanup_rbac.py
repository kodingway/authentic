from django.core.management.base import BaseCommand


class Command(BaseCommand):
    args = '<clean_threshold>'
    help = '''Clean dead permissions and roles'''

    def handle(self, *args, **options):
        from django_rbac.utils import get_permission_model, get_role_model

        Permission = get_permission_model()
        count = Permission.objects.cleanup()
        if count:
            print 'Deleted %d permissions.' % count

        Role = get_role_model()

        count = 0
        count = Role.objects.cleanup()
        if count:
            print 'Deleted %d roles.' % count
