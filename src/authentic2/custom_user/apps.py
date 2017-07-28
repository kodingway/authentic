from django.apps import AppConfig


class CustomUserConfig(AppConfig):
    name = 'authentic2.custom_user'
    verbose_name = 'Authentic2 Custom User App'

    def ready(self):
        from django.db.models.signals import post_migrate

        post_migrate.connect(
            self.create_first_name_last_name_attributes,
            sender=self)

    def create_first_name_last_name_attributes(self, app_config, **kwargs):
        from django.utils import translation
        from django.utils.translation import ugettext_lazy as _
        from django.conf import settings
        from authentic2.attribute_kinds import get_kind
        from authentic2.models import Attribute, AttributeValue
        from django.contrib.auth import get_user_model
        from django.contrib.contenttypes.models import ContentType

        if Attribute.objects.filter(name__in=['first_name', 'last_name']).count() == 2:
            return

        translation.activate(settings.LANGUAGE_CODE)
        User = get_user_model()
        content_type = ContentType.objects.get_for_model(User)

        attrs = {}
        attrs['first_name'], created = Attribute.objects.get_or_create(
            name='first_name',
            defaults={'kind': 'string',
                      'label': _('First name'),
                      'required': True,
                      'asked_on_registration': True,
                      'user_editable': True,
                      'user_visible': True})
        attrs['last_name'], created = Attribute.objects.get_or_create(
            name='last_name',
            defaults={'kind': 'string',
                      'label': _('Last name'),
                      'required': True,
                      'asked_on_registration': True,
                      'user_editable': True,
                      'user_visible': True})

        serialize = get_kind('string').get('serialize')
        for user in User.objects.all():
            for attr_name in attrs:
                av, created = AttributeValue.objects.get_or_create(
                    content_type=content_type,
                    object_id=user.id,
                    attribute=attrs[attr_name],
                    defaults={
                        'multiple': False,
                        'verified': False,
                        'content': serialize(getattr(user, attr_name, None))
                    })
