import pytest

from django.core.exceptions import ValidationError

from authentic2.custom_user.models import User


def test_user_clean_username(db, settings):
    settings.A2_USERNAME_IS_UNIQUE = True
    u1 = User.objects.create(username='john.doe', email='john.doe@example.net')
    # DoesNotExist
    u1.clean()
    u2 = User(username='john.doe', email='john.doe2@example.net')
    # found
    with pytest.raises(ValidationError):
        u2.clean()
    u2.save()
    u3 = User(username='john.doe', email='john.doe3@example.net')
    # MultipleObjectsReturned
    with pytest.raises(ValidationError):
        u3.clean()


def test_user_clean_email(db, settings):
    settings.A2_EMAIL_IS_UNIQUE = True
    u1 = User.objects.create(username='john.doe', email='john.doe@example.net')
    # DoesNotExist
    u1.clean()
    u2 = User(username='john.doe2', email='john.doe@example.net')
    # found
    with pytest.raises(ValidationError):
        u2.clean()
    u2.save()
    u3 = User(username='john.doe3', email='john.doe@example.net')
    # MultipleObjectsReturned
    with pytest.raises(ValidationError):
        u3.clean()
