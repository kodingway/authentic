import logging


from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render
from django.utils.translation import ugettext as _


from .. import models
from .. import app_settings


logger = logging.getLogger(__name__)


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
