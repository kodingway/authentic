import warnings
import re

from django.core.exceptions import ImproperlyConfigured
from django.utils import timezone
from django.core import validators
from django.db import models
from django.core.mail import send_mail
from django.utils.translation import ugettext as _
from django.contrib.auth.models import (AbstractBaseUser, PermissionsMixin,
        BaseUserManager, SiteProfileNotAvailable)
from django.contrib.auth import load_backend
from django.utils.http import urlquote

from idp.models import UserProfile


class UserManager(BaseUserManager):
    def create_user(self, username, email=None, password=None, **extra_fields):
        """
        Creates and saves a User with the given username, email and password.
        """
        now = timezone.now()
        if not username:
            raise ValueError('The given username must be set')
        email = UserManager.normalize_email(email)
        user = self.model(username=username, email=email,
                          is_staff=False, is_active=True, is_superuser=False,
                          last_login=now, date_joined=now, **extra_fields)

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password, **extra_fields):
        u = self.create_user(username, email, password, **extra_fields)
        u.is_staff = True
        u.is_active = True
        u.is_superuser = True
        u.save(using=self._db)
        return u


class AbstractUser(AbstractBaseUser, PermissionsMixin):
    """
    An abstract base class implementing a fully featured User model with
    admin-compliant permissions.

    Username, password and email are required. Other fields are optional.
    """
    username = models.CharField(_('username'), max_length=30, unique=True,
        help_text=_('Required. 30 characters or fewer. Letters, numbers and '
                    '@/./+/-/_ characters'),
        validators=[
            validators.RegexValidator(re.compile('^[\w.@+-]+$'), _('Enter a valid username.'), 'invalid')
        ])
    is_staff = models.BooleanField(_('staff status'), default=False,
        help_text=_('Designates whether the user can log into this admin '
                    'site.'))
    is_active = models.BooleanField(_('active'), default=True,
        help_text=_('Designates whether this user should be treated as '
                    'active. Unselect this instead of deleting accounts.'))
    date_joined = models.DateTimeField(_('date joined'), default=timezone.now)
    backend = models.CharField(max_length=64, blank=True)
    backend_id = models.CharField(max_length=256, blank=True)

    objects = UserManager()

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']

    class Meta:
        verbose_name = _('user')
        verbose_name_plural = _('users')
        abstract = True

    def get_absolute_url(self):
        return "/users/%s/" % urlquote(self.username)

    def get_full_name(self):
        """
        Returns the first_name plus the last_name, with a space in between.
        """
        full_name = '%s %s' % (self.first_name, self.last_name)
        return full_name.strip()

    def get_short_name(self):
        "Returns the short name for the user."
        return self.username

    def email_user(self, subject, message, from_email=None):
        """
        Sends an email to this User.
        """
        send_mail(subject, message, from_email, [self.email])

    def get_profile(self):
        """
        Returns site-specific profile for this user. Raises
        SiteProfileNotAvailable if this site does not allow profiles.
        """
        warnings.warn("The use of AUTH_PROFILE_MODULE to define user profiles has been deprecated.",
            DeprecationWarning, stacklevel=2)
        if not hasattr(self, '_profile_cache'):
            from django.conf import settings
            if not getattr(settings, 'AUTH_PROFILE_MODULE', False):
                raise SiteProfileNotAvailable(
                    'You need to set AUTH_PROFILE_MODULE in your project '
                    'settings')
            try:
                app_label, model_name = settings.AUTH_PROFILE_MODULE.split('.')
            except ValueError:
                raise SiteProfileNotAvailable(
                    'app_label and model_name should be separated by a dot in '
                    'the AUTH_PROFILE_MODULE setting')
            try:
                model = models.get_model(app_label, model_name)
                if model is None:
                    raise SiteProfileNotAvailable(
                        'Unable to load the profile model, check '
                        'AUTH_PROFILE_MODULE in your project settings')
                self._profile_cache = model._default_manager.using(
                                   self._state.db).get(user__id__exact=self.id)
                self._profile_cache.user = self
            except (ImportError, ImproperlyConfigured):
                raise SiteProfileNotAvailable
        return self._profile_cache

    def get_backend(self):
        return load_backend(self.backend)

    def has_usable_password(self):
        if self.backend:
            backend = self.get_backend()
            if hasattr(backend, 'has_usable_password'):
                return backend.has_usable_password(self)
        return super(AbstractUser, self).has_usable_password()

    def set_password(self, raw_password):
        if self.backend:
            backend = self.get_backend()
            if hasattr(backend, 'set_password'):
                return backend.set_password(self, raw_password)
        return super(AbstractUser, self).set_password(raw_password)

    def check_password(self, raw_password):
        if self.backend:
            backend = self.get_backend()
            if hasattr(backend, 'check_password'):
                return backend.check_password(self, raw_password)
        return super(AbstractUser, self).check_password(raw_password)

    def save(self, *args, **kwargs):
        no_backend = kwargs.pop('no_backend', False)
        if self.backend and not no_backend:
            backend = self.get_backend()
            if hasattr(backend, 'save'):
                if backend.save(self, *args, **kwargs):
                    return
        super(AbstractUser, self).save(*args, **kwargs)


class User(AbstractUser):
    first_name = models.CharField(_('first name'), max_length=30, blank=True)
    last_name = models.CharField(_('last name'), max_length=30, blank=True)
    email = models.EmailField(_('e-mail address'), blank=True)
    nickname = models.CharField(_('nickname'), max_length=50, blank=True)
    url = models.URLField(_('Website'), blank=True)
    company = models.CharField(verbose_name=_("Company"),
            max_length=50, blank=True)
    phone = models.CharField(verbose_name=_("Phone"),
            max_length=50, blank=True)
    postal_address = models.TextField(verbose_name=_("Postal address"),
            max_length=255, blank=True)
