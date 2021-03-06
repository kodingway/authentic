import pytest

from django.core.exceptions import ValidationError

from authentic2.custom_user.models import User
from authentic2.models import Attribute, AttributeValue


def test_user_clean_username(db, settings):
    settings.A2_USERNAME_IS_UNIQUE = True
    u1 = User.objects.create(username='john.doe', email='john.doe@example.net')
    u1.set_password('blank')
    # DoesNotExist
    u1.full_clean()
    u2 = User(username='john.doe', email='john.doe2@example.net')
    u2.set_password('blank')
    # found
    with pytest.raises(ValidationError):
        u2.full_clean()
    u2.save()
    u3 = User(username='john.doe', email='john.doe3@example.net')
    u3.set_password('blank')
    # MultipleObjectsReturned
    with pytest.raises(ValidationError):
        u3.full_clean()


def test_user_clean_email(db, settings):
    settings.A2_EMAIL_IS_UNIQUE = True
    u1 = User.objects.create(username='john.doe', email='john.doe@example.net')
    u1.set_password('blank')
    # DoesNotExist
    u1.full_clean()
    u2 = User(username='john.doe2', email='john.doe@example.net')
    u2.set_password('blank')
    # found
    with pytest.raises(ValidationError):
        u2.full_clean()
    u2.save()
    u3 = User(username='john.doe3', email='john.doe@example.net')
    u3.set_password('blank')
    # MultipleObjectsReturned
    with pytest.raises(ValidationError):
        u3.full_clean()


def test_user_has_verified_attributes(db, settings):
    attribute = Attribute.objects.create(name='phone', label='phone', kind='string')
    user = User(username='john.doe', email='john.doe2@example.net')
    user.save()
    assert user.has_verified_attributes() is False
    attribute_value = AttributeValue.objects.create(
            owner=user, attribute=attribute, content='0101010101')
    attribute_value.save()
    assert user.has_verified_attributes() is False
    attribute_value.verified = True
    attribute_value.save()
    assert user.has_verified_attributes() is True


def test_sync_first_name(db, settings):
    Attribute.objects.get_or_create(name='first_name', defaults={'label': 'First Name', 'kind':
                                                                 'string'})

    user = User(username='john.doe', email='john.doe2@example.net')
    user.save()
    user.first_name = 'John'
    user.save()
    assert user.attributes.first_name == 'John'

    user.attributes.first_name = 'John Paul'
    assert user.attributes.first_name == 'John Paul'
