from django.shortcuts import render_to_response
from django.template import RequestContext
from django.views.generic.edit import CreateView, UpdateView
import logging
from authentic2.idp.models import UserProfile
from authentic2.idp.decorators import prevent_access_to_transient_users

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
    model = UserProfile
    template_name = 'profiles/edit_profile.html'
    sucess_url = '/profile'

class CreateProfile(CreateView):
    model = UserProfile
    template_name = 'profiles/create_profile.html'
    sucess_url = '/profile'

edit_profile = prevent_access_to_transient_users(EditProfile.as_view())
create_profile = prevent_access_to_transient_users(CreateView.as_view())
