import logging

from django.utils.translation import ugettext as _
from django.shortcuts import render_to_response, redirect as shortcuts_redirect
from django.template import RequestContext
from django.views.generic.edit import UpdateView
from django.contrib import messages
from django.contrib.auth import get_user_model


from authentic2.idp.decorators import prevent_access_to_transient_users

import forms

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
    success_url = '/profile'

    def get_object(self):
        return self.request.user

edit_profile = prevent_access_to_transient_users(EditProfile.as_view())

def password_change_done(request):
    '''Redirect user to homepage and display a success message'''
    messages.info(request, _('Your password has been changed'))
    return shortcuts_redirect('account_management')
