import logging

from django.conf import settings
from django.shortcuts import render, get_object_or_404
from django.utils.translation import ugettext as _
from django.contrib import messages
from django.contrib.auth import login as django_login, logout, REDIRECT_FIELD_NAME
from django.core import signing
from django.views.generic.edit import FormView, CreateView
from django.views.generic.base import TemplateView
from django.contrib.auth import get_user_model
from django.forms import CharField

from authentic2.utils import import_module_or_class, redirect, make_url, get_fields_and_labels
from authentic2.a2_rbac.utils import get_default_ou

from django_rbac.utils import get_ou_model

from .. import models, app_settings, compat, cbv, views, forms, validators
from .forms import RegistrationCompletionForm
from authentic2.a2_rbac.models import OrganizationalUnit

logger = logging.getLogger(__name__)

User = compat.get_user_model()

def valid_token(method):
    def f(request, *args, **kwargs):
        try:
            request.token = signing.loads(kwargs['registration_token'],
                                                max_age=settings.ACCOUNT_ACTIVATION_DAYS*3600*24)
        except signing.SignatureExpired:
            messages.warning(request, _('Your activation key is expired'))
            return redirect(request, 'registration_register')
        except signing.BadSignature:
            messages.warning(request, _('Activation failed'))
            return redirect(request, 'registration_register')
        return method(request, *args, **kwargs)
    return f

def login(request, user):
    user.backend = 'authentic2.backends.models_backend.ModelBackend'
    django_login(request, user)

class RegistrationView(cbv.ValidateCSRFMixin, FormView):
    form_class = import_module_or_class(app_settings.A2_REGISTRATION_FORM_CLASS)
    template_name = 'registration/registration_form.html'

    def form_valid(self, form):
        form.save(self.request)
        return redirect(self.request, 'registration_complete')

class RegistrationCompletionView(CreateView):
    model = get_user_model()
    template_name = 'registration/registration_completion_form.html'
    success_url = 'auth_homepage'

    def get_success_url(self):
        if self.token and self.token.get(REDIRECT_FIELD_NAME):
            return self.token[REDIRECT_FIELD_NAME]
        return make_url(self.success_url)

    def dispatch(self, request, *args, **kwargs):
        self.token = request.token
        self.email = request.token['email']
        if 'ou' in self.token:
            self.ou = OrganizationalUnit.objects.get(pk=self.token['ou'])
        else:
            self.ou = None
        self.users = User.objects.filter(email__iexact=self.email) \
            .order_by('date_joined')
        self.email_is_unique = app_settings.A2_EMAIL_IS_UNIQUE \
            or app_settings.A2_REGISTRATION_EMAIL_IS_UNIQUE
        if self.ou:
            self.email_is_unique |= self.ou.email_is_unique
        self.init_fields_labels_and_help_texts()
        return super(RegistrationCompletionView, self) \
            .dispatch(request, *args, **kwargs)

    def init_fields_labels_and_help_texts(self):
        attributes = models.Attribute.objects.filter(
            asked_on_registration=True)
        default_fields = attributes.values_list('name', flat=True)
        required_fields = models.Attribute.objects.filter(required=True) \
            .values_list('name', flat=True)
        fields, labels = get_fields_and_labels(
            app_settings.A2_REGISTRATION_FIELDS,
            default_fields,
            app_settings.A2_REGISTRATION_REQUIRED_FIELDS,
            app_settings.A2_REQUIRED_FIELDS,
            models.Attribute.objects.filter(required=True).values_list('name', flat=True))
        help_texts = {}
        if app_settings.A2_REGISTRATION_FORM_USERNAME_LABEL:
            labels['username'] = \
                    app_settings.A2_REGISTRATION_FORM_USERNAME_LABEL
        if app_settings.A2_REGISTRATION_FORM_USERNAME_HELP_TEXT:
            help_texts['username'] = \
                app_settings.A2_REGISTRATION_FORM_USERNAME_HELP_TEXT
        required = list(app_settings.A2_REGISTRATION_REQUIRED_FIELDS) + \
            list(required_fields)
        if 'email' in fields:
            fields.remove('email')
        self.fields = fields
        self.labels = labels
        self.required = required
        self.help_texts = help_texts

    def get_form_class(self):
        form_class = forms.modelform_factory(self.model,
                                             form=RegistrationCompletionForm,
                                             fields=self.fields,
                                             labels=self.labels,
                                             required=self.required,
                                             help_texts=self.help_texts)
        if 'username' in self.fields and app_settings.A2_REGISTRATION_FORM_USERNAME_REGEX:
            # Keep existing field label and help_text
            old_field = form_class.base_fields['username']
            field = CharField(max_length=256, label=old_field.label, help_text=old_field.help_text,
                    validators=[validators.UsernameValidator()])
            form_class = type('RegistrationForm', (form_class,), {'username': field})
        return form_class

    def get_form_kwargs(self, **kwargs):
        '''Initialize mail from token'''
        kwargs = super(RegistrationCompletionView, self).get_form_kwargs(**kwargs)
        if 'ou' in self.token:
            OU = get_ou_model()
            ou = get_object_or_404(OU, id=self.token['ou'])
        else:
            ou = get_default_ou()
        kwargs['instance'] = get_user_model()(
            email=self.email,
            ou=ou)
        return kwargs

    def get_context_data(self, **kwargs):
        ctx = super(RegistrationCompletionView, self).get_context_data(**kwargs)
        ctx['token'] = self.token
        ctx['users'] = self.users
        ctx['email'] = self.email
        ctx['email_is_unique'] = self.email_is_unique
        ctx['create'] = 'create' in self.request.GET
        return ctx

    def get(self, request, *args, **kwargs):
        if len(self.users) == 1 and self.email_is_unique:
            # Found one user, EMAIL is unique, log her in
            login(request, self.users[0])
            return redirect(request, self.get_success_url())
        if all(field in self.token for field in self.fields):
            # We already have every fields
            form_kwargs = self.get_form_kwargs()
            form_class = self.get_form_class()
            data = self.token
            if 'password' in data:
                data['password1'] = data['password']
                data['password2'] = data['password']
                del data['password']
            form_kwargs['data'] = data
            form = form_class(**form_kwargs)
            if form.is_valid():
                user = form.save()
                login(request, user)
                return redirect(request, self.get_success_url())
            self.get_form = lambda *args, **kwargs: form
        return super(RegistrationCompletionView, self).get(request, *args,
                                                           **kwargs)

    def post(self, request, *args, **kwargs):
        if self.users and self.email_is_unique:
            return redirect(request, request.resolver_match.view_name,
                    args=self.args, kwargs=self.kwargs)
        if 'uid' in request.POST:
            uid = request.POST['uid']
            for user in self.users:
                if str(user.id) == uid:
                    login(request, user)
                    return redirect(request, self.get_success_url())
        return super(RegistrationCompletionView, self).post(request, *args, **kwargs)

    def form_valid(self, form):
        ret = super(RegistrationCompletionView, self).form_valid(form)
        login(self.request, self.object)
        return ret

class DeleteView(TemplateView):
    def get(self, request, *args, **kwargs):
        if not app_settings.A2_REGISTRATION_CAN_DELETE_ACCOUNT:
            return redirect(request, '..')
        return render(request, 'registration/delete_account.html')

    def post(self, request, *args, **kwargs):
        if 'submit' in request.POST:
            models.DeletedUser.objects.delete_user(request.user)
            logger.info(u'deletion of account %s requested', request.user)
            messages.info(request, _('Your account has been scheduled for deletion. You cannot use it anymore.'))
            return redirect(request, 'auth_logout')
        else:
            return redirect(request, '..')

registration_completion = valid_token(RegistrationCompletionView.as_view())
