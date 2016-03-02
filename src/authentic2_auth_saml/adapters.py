from mellon.adapters import DefaultAdapter
from django.contrib.auth import get_user_model

class AuthenticAdapter(DefaultAdapter):
    def create_user(self, user_class):
        return user_class.objects.create()

    def finish_create_user(self, idp, saml_attributes, user):
        pass
