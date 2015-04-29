import logging

from django.conf import settings
from django.shortcuts import render
from django.utils.translation import ugettext as _
from django.contrib import messages
from django.contrib.auth import login as django_login, logout, REDIRECT_FIELD_NAME
from django.core import signing
from django.views.generic.edit import FormView, CreateView
from django.views.generic.base import TemplateView
from django.contrib.auth import get_user_model
from django.forms import CharField

from authentic2.utils import get_form_class, redirect, make_url, get_fields_and_labels
from .. import models, app_settings, compat, cbv, views, forms, validators
from .forms import RegistrationCompletionForm

logger = logging.getLogger(__name__)

User = compat.get_user_model()

def valid_token(method):
    def f(request, *args, **kwargs):
        try:
            request.token = signing.loads(kwargs['registration_token'],
                                                max_age=settings.ACCOUNT_ACTIVATION_DAYS*3600*24)
        except signing.SignatureExpired:
            return redirect(request, 'registration_activation_expired')
        except signing.BadSignature:
            return redirect(request, 'registration_activation_failed')
        return method(request, *args, **kwargs)
    return f

def login(request, user):
    user.backend = 'authentic2.backends.models_backend.ModelBackend'
    django_login(request, user)

class RegistrationView(cbv.ValidateCSRFMixin, FormView):
    form_class = get_form_class(app_settings.A2_REGISTRATION_FORM_CLASS)
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
        self.users = User.objects.filter(email__iexact=self.email) \
            .order_by('date_joined')
        self.email_is_unique = app_settings.A2_EMAIL_IS_UNIQUE \
            or app_settings.A2_REGISTRATION_EMAIL_IS_UNIQUE
        return super(RegistrationCompletionView, self) \
            .dispatch(request, *args, **kwargs)

    def get_form_class(self):
        attributes = models.Attribute.objects.filter(
                asked_on_registration=True)
        default_fields = attributes.values_list('name', flat=True)
        fields, labels = get_fields_and_labels(
            app_settings.A2_REGISTRATION_FIELDS,
            default_fields,
            app_settings.A2_REGISTRATION_REQUIRED_FIELDS,
            app_settings.A2_REQUIRED_FIELDS,
            models.Attribute.objects.filter(required=True).values_list('name', flat=True))
        help_texts = {}
        if app_settings.A2_REGISTRATION_FORM_USERNAME_LABEL:
            labels['username'] = app_settings.A2_REGISTRATION_FORM_USERNAME_LABEL
        if app_settings.A2_REGISTRATION_FORM_USERNAME_HELP_TEXT:
            help_texts['username'] = app_settings.A2_REGISTRATION_FORM_USERNAME_HELP_TEXT
        required = app_settings.A2_REGISTRATION_REQUIRED_FIELDS
        if 'email' in fields:
            fields.remove('email')
        form_class = forms.modelform_factory(self.model,
                form=RegistrationCompletionForm, fields=fields, labels=labels,
                required=required, help_texts=help_texts)
        if 'username' in fields and app_settings.A2_REGISTRATION_FORM_USERNAME_REGEX:
            # Keep existing field label and help_text
            old_field = form_class.base_fields['username']
            field = CharField(max_length=256, label=old_field.label, help_text=old_field.help_text,
                    validators=[validators.UsernameValidator()])
            form_class = type('RegistrationForm', (form_class,), {'username': field})
        return form_class
    

    def get_form_kwargs(self, **kwargs):
        '''Initialize mail from token'''
        kwargs = super(RegistrationCompletionView, self).get_form_kwargs(**kwargs)
        kwargs['instance'] = get_user_model()(email=self.request.token['email'])
        return kwargs

    def get_context_data(self, **kwargs):
        ctx = super(RegistrationCompletionView, self).get_context_data(**kwargs)
        ctx['token'] = self.token
        ctx['users'] = self.users
        ctx['email'] = self.token['email']
        ctx['email_is_unique'] = self.email_is_unique
        ctx['create'] = 'create' in self.request.GET
        return ctx

    def get(self, request, *args, **kwargs):
        if len(self.users) == 1 and self.email_is_unique:
            # Found one user, EMAIL is unique, log her in
            login(request, self.users[0])
            return redirect(request, self.get_success_url())
        return super(RegistrationCompletionView, self).get(request, *args, **kwargs)

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
        next_url = request.build_absolute_uri(request.META.get('HTTP_REFERER')\
                                              or request.GET.get('next_url'))
        if not app_settings.A2_REGISTRATION_CAN_DELETE_ACCOUNT:
            return redirect(request, next_url)
        return render(request, 'registration/delete_account.html')

    def post(self, request, *args, **kwargs):
        next_url = request.build_absolute_uri(request.META.get('HTTP_REFERER')\
                                              or request.GET.get('next_url'))
        if 'submit' in request.POST:
            models.DeletedUser.objects.delete_user(request.user)
            logger.info(u'deletion of account %s requested' % request.user)
            messages.info(request, _('Your account has been scheduled for deletion. You cannot use it anymore.'))
            return redirect(request, 'auth_logout')
        else:
            return redirect(request, next_url)

registration_completion = valid_token(RegistrationCompletionView.as_view())
