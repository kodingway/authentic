from django.utils.translation import ugettext as _
from django.conf import settings
from django.apps import apps
from django.utils.translation import override
from django.db import DEFAULT_DB_ALIAS, router

from ..utils import get_fk_model
from django_rbac.utils import get_ou_model, get_role_model

from .management import update_rbac


def create_default_ou(app_config, verbosity=2, interactive=True,
                      using=DEFAULT_DB_ALIAS, **kwargs):
    if not router.allow_migrate(using, get_ou_model()):
        return
    # be sure new objects names are localized using the default locale
    with override(settings.LANGUAGE_CODE):
        OrganizationalUnit = get_ou_model()
        if OrganizationalUnit.objects.exists():
            return
        # Create a default OU if none exists currently
        default_ou, created = OrganizationalUnit.objects.get_or_create(
            slug='defaut',
            defaults={
                'default': True,
                'name': _('Default organizational unit'),
            })
        # Update all existing models having an ou field to the default ou
        for app in apps.get_app_configs():
            for model in app.get_models():
                related_model = get_fk_model(model, 'ou')
                if not related_model == OrganizationalUnit:
                    return
                model.objects.filter(ou__isnull=True).update(ou=default_ou)


def post_migrate_update_rbac(app_config, verbosity=2, interactive=True,
                             using=DEFAULT_DB_ALIAS, **kwargs):
    # be sure new objects names are localized using the default locale
    if not router.allow_migrate(using, get_role_model()):
        return
    with override(settings.LANGUAGE_CODE):
        update_rbac()


def update_rbac_on_save(sender, instance, created, raw, **kwargs):
    update_rbac()


def update_service_role_ou(sender, instance, created, raw, **kwargs):
    get_role_model().objects.filter(service=instance).update(ou=instance.ou)
