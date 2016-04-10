import lasso

from mellon.adapters import DefaultAdapter
from mellon.utils import get_setting
from django.contrib.auth import get_user_model

from authentic2.models import UserExternalId


class AuthenticAdapter(DefaultAdapter):
    def lookup_user(self, idp, saml_attributes):
        if saml_attributes.get('name_id_format') == lasso.SAML2_NAME_IDENTIFIER_FORMAT_TRANSIENT:
            federated_attribute = get_setting(idp, 'FEDERATED_ATTRIBUTE')
            if not federated_attribute in saml_attributes:
                return None
            federated_attribute_v = saml_attributes[federated_attribute]
            ueis = (UserExternalId.objects.filter(source=saml_attributes['issuer'],
                                                  external_id=federated_attribute_v)
                    .order_by('pk'))
            if len(ueis) == 0:
                user = self.create_user(get_user_model())
                new_uei, created = UserExternalId.objects.get_or_create(
                    user=user,
                    source=saml_attributes['issuer'],
                    external_id=federated_attribute_v)
                # check for concurrent creations
                # all creations must be done under the AUTOCOMMIT policy, meaning that any other
                # creation has already happened before and is visible or will happen after and this
                # one will be visible
                for uei in ueis.all().order_by('pk'):
                    if uei.pk < new_uei.pk:
                        new_uei.delete()
                        user.delete()
                        return uei.user
                    break
                self.finish_create_user(user)
                return user
            return ueis[0].user
        return super(AuthenticAdapter, self).lookup_user(idp, saml_attributes)

    def create_user(self, user_class):
        return user_class.objects.create()

    def finish_create_user(self, idp, saml_attributes, user):
        pass
