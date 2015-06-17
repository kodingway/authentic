from django.views.generic import FormView
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.utils.translation import ugettext as _
from django.utils.http import urlsafe_base64_decode

from .registration_backend.forms import SetPasswordForm
from . import cbv, profile_forms, utils


class PasswordResetView(cbv.NextURLViewMixin, FormView):
    '''Ask for an email and send a password reset link by mail'''
    form_class = profile_forms.PasswordResetForm
    email_template_name = [
        'authentic2/password_reset_email_body.txt',
        'registration/password_reset_email.html',
    ]
    html_email_template_name = [
        'authentic2/password_reset_email_body.txt',
    ]
    subject_template_name = [
        'authentic2/password_reset_email_subject.txt',
        'registration/password_reset_subject.txt',
    ]

    def get_template_names(self):
        return [
            'authentic2/password_reset_form.html',
            'registration/password_reset_form.html',
        ]

    def get_context_data(self, **kwargs):
        ctx = super(PasswordResetView, self).get_context_data(**kwargs)
        ctx['title'] = _('Password reset')
        return ctx

    def form_valid(self, form):
        opts = {
            'use_https': self.request.is_secure(),
            'token_generator': default_token_generator,
            'from_email': None,
            'email_template_name': self.email_template_name,
            'subject_template_name': self.subject_template_name,
            'request': self.request,
            'html_email_template_name': self.html_email_template_name,
        }
        form.save(**opts)
        # return to next URL
        messages.info(self.request, _('A mail was sent to you with '
                                      'instructions to reset your password'))
        return super(PasswordResetView, self).form_valid(form)

password_reset = PasswordResetView.as_view()


class PasswordResetConfirmView(cbv.RedirectToNextURLViewMixin, FormView):
    '''Validate password reset link, show a set password form and login
       the user.
    '''
    form_class = SetPasswordForm

    def get_template_names(self):
        return [
            'registration/password_reset_confirm.html',
            'authentic2/password_reset_confirm.html',
        ]

    def dispatch(self, request, *args, **kwargs):
        validlink = True
        uidb64 = kwargs['uidb64']
        token = kwargs['token']

        UserModel = get_user_model()
        # checked by URLconf
        assert uidb64 is not None and token is not None
        try:
            uid = urlsafe_base64_decode(uidb64)
            self.user = UserModel._default_manager.get(pk=uid)
        except (TypeError, ValueError, OverflowError,
                UserModel.DoesNotExist):
            validlink = False
            messages.warning(request, _('User not found'))

        if validlink and not default_token_generator.check_token(self.user, token):
            validlink = False
            messages.warning(request, _('You reset password link is invalid '
                                        'or has expired'))
        if not validlink:
            return utils.redirect(request, self.get_success_url())
        return super(PasswordResetConfirmView, self).dispatch(request, *args,
                                                              **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super(PasswordResetConfirmView, self).get_context_data(**kwargs)
        # compatibility with existing templates !
        ctx['title'] = _('Enter new password')
        ctx['validlink'] = True
        return ctx

    def get_form_kwargs(self):
        kwargs = super(PasswordResetConfirmView, self).get_form_kwargs()
        kwargs['user'] = self.user
        return kwargs

    def form_valid(self, form):
        super(PasswordResetConfirmView, self).form_valid(form)
        self.user.backend = 'authentic2.backends.models_backend.ModelBackend'
        return utils.login(self.request, self.user, 'email')

password_reset_confirm = PasswordResetConfirmView.as_view()
