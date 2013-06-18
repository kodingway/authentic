import logging
import lasso
import thread


import requests


from django.conf import settings
from django.utils.translation import ugettext as _
from django.shortcuts import render_to_response, redirect as shortcuts_redirect, render
from django.template import RequestContext
from django.views.generic.edit import UpdateView
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404
from django.contrib.auth import SESSION_KEY
from django import http
from django.contrib.auth.decorators import login_required


from authentic2.idp.decorators import prevent_access_to_transient_users
from authentic2.idp.saml import saml2_endpoints
from authentic2.saml import models as saml_models


import forms
import models
import app_settings


logger = logging.getLogger(__name__)


def redirect(request, next, template_name='redirect.html'):
    '''Show a simple page which does a javascript redirect, closing any popup
       enclosing us'''
    if not next.startswith('http'):
        next = '/%s%s' % (request.get_host(), next)
    logging.info('Redirect to %r' % next)
    return render_to_response(template_name, { 'next': next })


def server_error(request, template_name='500.html'):
    """
    500 error handler.

    Templates: `500.html`
    Context: None
    """
    return render_to_response(template_name,
        context_instance = RequestContext(request)
    )


def registration_success(request, template_name='registration/registration_complete.html'):
    """
    Return page after a successful registration.
    """
    return render_to_response(template_name,
        context_instance = RequestContext(request)
    )


class EditProfile(UpdateView):
    model = get_user_model()
    form_class = forms.UserProfileForm
    template_name = 'profiles/edit_profile.html'
    success_url = '../'

    def get_object(self):
        return self.request.user

    def push_attributes(self):
        # Push attributes to SP
        # Policy must not require user consent
        federations = \
            saml_models.LibertyFederation.objects.filter(user=self.request.user)
        for federation in federations:
            sp_id = federation.sp_id
            login = saml2_endpoints.idp_sso(self.request,
                sp_id, save=False, return_profile=True)
            if login.msgBody:
                # Only with SP supporting SSO IdP-initiated by POST
                url = login.msgUrl
                data = { lasso.SAML2_FIELD_RESPONSE: login.msgBody }
                try:
                    session = requests.Session()
                    session.post(url, data=data, allow_redirects=True, timeout=5)
                except:
                    logger.exception('exception when pushing attributes '
                            'of %s to %s', self.request.user,
                            sp_id)
                else:
                    logger.info('pushing attributes of %s to %s',
                            self.request.user, sp_id)

    def form_valid(self, form):
        if settings.PUSH_PROFILE_UPDATES:
            thread.start_new_thread(self.push_attributes, ())
        return super(EditProfile, self).form_valid(form)


edit_profile = prevent_access_to_transient_users(EditProfile.as_view())


def password_change_done(request):
    '''Redirect user to homepage and display a success message'''
    messages.info(request, _('Your password has been changed'))
    return shortcuts_redirect('account_management')


def su(request, username, redirect_url='/'):
    '''To use this view add:

       url(r'^su/(?P<username>.*)/$', 'authentic2.views.su', {'redirect_url': '/'}),
    '''
    if request.user.is_superuser or request.session.get('has_superuser_power'):
        su_user = get_object_or_404(get_user_model(), username=username)
        if su_user.is_active:
            request.session[SESSION_KEY] = su_user.id
            request.session['has_superuser_power'] = True
            return http.HttpResponseRedirect(redirect_url)
    else:
        return http.HttpResponseRedirect('/')


@login_required
def delete_account(request, next_url='/'):
    next_url = request.build_absolute_uri(request.META.get('HTTP_REFERER') or next_url)
    if not app_settings.ALLOW_ACCOUNT_DELETION:
        return shortcuts_redirect(next_url)
    if request.method == 'POST':
        if 'submit' in request.POST:
            models.DeletedUser.objects.delete_user(request.user)
            logger.info(u'deletion of account %s requested' % request.user)
            return shortcuts_redirect('auth_logout')
        else:
            return shortcuts_redirect(next_url)
    return render(request, 'registration/delete_account.html')
