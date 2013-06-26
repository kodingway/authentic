from django.utils.importlib import import_module


from registration.backends.default import DefaultBackend


from .. import app_settings


class RegistrationBackend(DefaultBackend):
    def get_form_class(self, request):
        form_class = app_settings.A2_REGISTRATION_FORM_CLASS
        module, form_class = form_class.rsplit('.', 1)
        module = import_module(module)
        return getattr(module, form_class)
