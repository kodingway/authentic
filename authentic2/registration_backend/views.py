import logging


from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render
from django.utils.translation import ugettext as _


from registration.backends.default.views import RegistrationView as BaseRegistrationView


from .. import models, app_settings, compat
from . import urls


logger = logging.getLogger(__name__)


class RegistrationView(BaseRegistrationView):
    form_class = urls.get_form_class(app_settings.A2_REGISTRATION_FORM_CLASS)

    def register(self, request, **cleaned_data):
        User = compat.get_user_model()
        new_user = super(RegistrationView, self).register(request, **cleaned_data)
        for field in User.REQUIRED_FIELDS:
            setattr(new_user, field, cleaned_data.get(field))
        new_user.save()
        return new_user

register = RegistrationView.as_view()


@login_required
def delete(request, next_url='/'):
    next_url = request.build_absolute_uri(request.META.get('HTTP_REFERER') or next_url)
    if not app_settings.A2_REGISTRATION_CAN_DELETE_ACCOUNT:
        return redirect(next_url)
    if request.method == 'POST':
        if 'submit' in request.POST:
            models.DeletedUser.objects.delete_user(request.user)
            logger.info(u'deletion of account %s requested' % request.user)
            messages.info(request, _('Your account has been scheduled for deletion. You cannot use it anymore.'))
            return redirect('auth_logout')
        else:
            return redirect(next_url)
    return render(request, 'registration/delete_account.html')
