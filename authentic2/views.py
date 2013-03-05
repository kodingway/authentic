import logging

from django.utils.translation import ugettext as _
from django.shortcuts import render_to_response, redirect as shortcuts_redirect
from django.template import RequestContext
from django.views.generic.edit import CreateView, UpdateView
from django.contrib import messages


from authentic2.idp.models import UserProfile
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

class ProfileMixin(object):
    model = UserProfile
    form_class = forms.UserProfileForm
    template_name = 'profiles/edit_profile.html'
    success_url = '/profile'

    def get_form_kwargs(self):
        kwargs = super(ProfileMixin, self).get_form_kwargs()
        kwargs['user'] = self.request.user
        return kwargs

class EditProfile(ProfileMixin, UpdateView):
    def get_object(self):
        return self.request.user.get_profile()

class CreateProfile(ProfileMixin, CreateView):
    template_name = 'profiles/create_profile.html'

edit_profile = prevent_access_to_transient_users(EditProfile.as_view())
create_profile = prevent_access_to_transient_users(CreateProfile.as_view())
