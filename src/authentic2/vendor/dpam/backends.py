import pam

from django.conf import settings


from authentic2.compat import get_user_model


class PAMBackend:
    def authenticate(self, username=None, password=None):
        User = get_user_model()
        service = getattr(settings, 'PAM_SERVICE', 'login')
        if pam.authenticate(username, password, service=service):
            try:
                user = User.objects.get(username=username)
            except:
                user = User(username=username, password='not stored here')

                if getattr(settings, 'PAM_IS_SUPERUSER', False):
                  user.is_superuser = True

                if getattr(settings, 'PAM_IS_STAFF', user.is_superuser):
                  user.is_staff = True

                user.save()
            return user
        return None

    def get_user(self, user_id):
        User = get_user_model()
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
