import pytest

from django.contrib.auth import get_user_model
from authentic2.models import Attribute

pytestmark = pytest.mark.django_db


def test_provision_attributes():
    from authentic2_auth_saml.adapters import AuthenticAdapter

    adapter = AuthenticAdapter()
    User = get_user_model()
    Attribute.objects.create(kind='title', name='title', label='title')

    user = User.objects.create()
    idp = {
        'A2_ATTRIBUTE_MAPPING': [
            {
                'attribute': 'email',
                'saml_attribute': 'mail',
                'mandatory': True,
            },
            {
                'attribute': 'title',
                'saml_attribute': 'title',
            },
        ]
    }

    saml_attributes = {
        u'mail': u'john.doe@example.com',
        u'title': u'Mr.',
    }
    adapter.finish_create_user(idp, saml_attributes, user)
    assert user.email == 'john.doe@example.com'
    assert user.attributes.title == 'Mr.'
    del saml_attributes['mail']
    with pytest.raises(ValueError):
        adapter.finish_create_user(idp, saml_attributes, user)
