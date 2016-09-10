import django
import collections
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
from django.forms import CharField, Form
from django.core.urlresolvers import reverse_lazy
from django.template import RequestContext

from authentic2.utils import import_module_or_class, redirect, make_url, get_fields_and_labels
from authentic2.a2_rbac.utils import get_default_ou

from django_rbac.utils import get_ou_model

from .. import models, app_settings, compat, cbv, views, forms, validators, utils
from .forms import RegistrationCompletionForm, DeleteAccountForm
from .forms import RegistrationCompletionFormNoPassword
from authentic2.a2_rbac.models import OrganizationalUnit

logger = logging.getLogger(__name__)

User = compat.get_user_model()

legacy_template_names = {
    'legacy_subject_templates': ['registration/activation_email_subject.txt'],
    'legacy_body_templates': ['registration/activation_email.txt'],
    'legacy_html_body_templates': ['registration/activation_email.html']
}

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

    def get_context_data(self, **kwargs):
        ctx = super(RegistrationView, self).get_context_data(**kwargs)
        request_context = RequestContext(self.request)
        request_context.push(ctx)
        if django.VERSION >= (1, 8, 0):
            request_context['add_to_blocks'] = collections.defaultdict(lambda: [])
        parameters = {'request': self.request,
                      'context_instance': request_context}
        blocks = [utils.get_backend_method(backend, 'registration', parameters)
                  for backend in utils.get_backends('AUTH_FRONTENDS')]
        request_context['frontends'] = collections.OrderedDict((block['id'], block)
                                                               for block in blocks if block)
        return request_context


class RegistrationCompletionView(CreateView):
    model = get_user_model()
    success_url = 'auth_homepage'

    def get_template_names(self):
        if self.users and not 'create' in self.request.GET:
            return ['registration/registration_completion_choose.html']
        else:
            return ['registration/registration_completion_form.html']

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
        if self.ou:
            self.users = self.users.filter(ou=self.ou)
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
        for field in self.token.get('skip_fields') or []:
            if field in fields:
                fields.remove(field)
        self.fields = fields
        self.labels = labels
        self.required = required
        self.help_texts = help_texts

    def get_form_class(self):
        if not self.token.get('valid_email', True):
            self.fields.append('email')
            self.required.append('email')
        form_class = RegistrationCompletionForm
        if self.token.get('no_password', False):
            form_class = RegistrationCompletionFormNoPassword
        form_class = forms.modelform_factory(self.model,
                                             form=form_class,
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

        attributes = {'email': self.email, 'ou': ou}
        logger.debug(u'attributes %s', attributes)

        prefilling_list = utils.accumulate_from_backends(self.request, 'registration_form_prefill')
        logger.debug(u'prefilling_list %s', prefilling_list)
        # Build a single meaningful prefilling with sets of values
        prefilling = {}
        for p in prefilling_list:
            for name, values in p.items():
                if name in self.fields:
                    prefilling.setdefault(name, set()).update(values)
        logger.debug(u'prefilling %s', prefilling)

        for name, values in prefilling.items():
            attributes[name] = ' '.join(values)
        logger.debug(u'attributes with prefilling %s', attributes)

        if self.token.get('user_id'):
            kwargs['instance'] = User.objects.get(id=self.token.get('user_id'))
        else:
            kwargs['instance'] = get_user_model()(**attributes)

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
        if all(field in self.token for field in self.fields) \
                and not self.token.get('confirm_data', False):
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
            # email is unique, users already exist, creating a new one is forbidden !
            return redirect(request, request.resolver_match.view_name, args=self.args,
                            kwargs=self.kwargs)
        if 'uid' in request.POST:
            uid = request.POST['uid']
            for user in self.users:
                if str(user.id) == uid:
                    login(request, user)
                    return redirect(request, self.get_success_url())
        return super(RegistrationCompletionView, self).post(request, *args, **kwargs)

    def form_valid(self, form):

        # remove verified fields from form, this allows an authentication
        # method to provide verified data fields and to present it to the user,
        # while preventing the user to modify them.
        for av in models.AttributeValue.objects.with_owner(form.instance):
            if av.verified and av.attribute.name in form.fields:
                del form.fields[av.attribute.name]

        if 'email' in self.request.POST and (not 'email' in self.token or
                                             self.request.POST['email'] !=
                                             self.token['email']) and not self.token.get('skip_email_check'):
            # If an email is submitted it must be validated or be the same as in the token
            data = form.cleaned_data
            data['no_password'] = self.token.get('no_password', False)
            utils.send_registration_mail(self.request,
                                   template_names=[],
                                   legacy_template_names=legacy_template_names,
                                   next_url=self.get_success_url(),
                                   **data)
            return redirect(self.request, 'registration_complete')
        ret = super(RegistrationCompletionView, self).form_valid(form)
        login(self.request, self.object)
        return ret

class DeleteView(FormView):
    template_name = 'authentic2/accounts_delete.html'
    success_url = reverse_lazy('auth_logout')

    def dispatch(self, request, *args, **kwargs):
        if not app_settings.A2_REGISTRATION_CAN_DELETE_ACCOUNT:
            return redirect(request, '..')
        return super(DeleteView, self).dispatch(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        if 'cancel' in request.POST:
            return redirect(request, 'account_management')
        return super(DeleteView, self).post(request, *args, **kwargs)

    def get_form_class(self):
        if self.request.user.has_usable_password():
            return DeleteAccountForm
        return Form

    def get_form_kwargs(self, **kwargs):
        kwargs = super(DeleteView, self).get_form_kwargs(**kwargs)
        if self.request.user.has_usable_password():
            kwargs['user'] = self.request.user
        return kwargs

    def form_valid(self, form):
        models.DeletedUser.objects.delete_user(self.request.user)
        logger.info(u'deletion of account %s requested', self.request.user)
        messages.info(self.request, _('Your account has been scheduled for deletion. You cannot use it anymore.'))
        return super(DeleteView, self).form_valid(form)

registration_completion = valid_token(RegistrationCompletionView.as_view())
