import logging

from django.views.generic import FormView
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.utils.translation import ugettext as _
from django.utils.http import urlsafe_base64_decode

from .compat import default_token_generator
from .registration_backend.forms import SetPasswordForm
from . import cbv, profile_forms, utils


class PasswordResetView(cbv.NextURLViewMixin, FormView):
    '''Ask for an email and send a password reset link by mail'''
    form_class = profile_forms.PasswordResetForm

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
        form.save()
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
        self.token = token = kwargs['token']

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
        if not self.user.has_usable_password():
            messages.warning(request, _('Account has no password, you cannot reset it.'))
            return self.finish()
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
        # Changing password by mail validate the email
        form.user.email_verified = True
        form.save()
        logging.getLogger(__name__).info(u'user %s resetted its password with '
                                         'token %r...', self.user,
                                         self.token[:9])
        return self.finish()

    def finish(self):
        return utils.simulate_authentication(self.request, self.user, 'email')

password_reset_confirm = PasswordResetConfirmView.as_view()


def switch_back(request):
    return utils.switch_back(request)
