from django.db import models
from authentic2.models import AbstractUser

class User(AbstractUser):
    first_name = models.CharField(_('first name'), max_length=64, blank=True)
    last_name = models.CharField(_('last name'), max_length=64, blank=True)
    email = models.EmailField(_('e-mail address'), max_length=128, blank=True)
    nickname = models.CharField(_('nickname'), max_length=50, blank=True)
    url = models.URLField(_('Website'), blank=True)
    company = models.CharField(verbose_name=_("Company"),
            max_length=50, blank=True)
    phone = models.CharField(verbose_name=_("Phone"),
            max_length=50, blank=True)
    postal_address = models.TextField(verbose_name=_("Postal address"),
            max_length=255, blank=True)

    USER_PROFILE = ( 'username', 'first_name', 'last_name', 'email',
            'nickname', 'url', 'phone', ('roles', _('roles')),)

    class Meta:
        db_table = 'authentic2_user'
