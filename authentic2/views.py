import logging
import lasso
import thread


import requests


from django.conf import settings
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.template.loader import render_to_string
from django.views.generic.edit import UpdateView, FormView
from django.views.generic import RedirectView, TemplateView
from django.contrib.auth import SESSION_KEY
from django import http, shortcuts
from django.core import mail, signing
from django.core.urlresolvers import reverse
from django.contrib.sites.models import get_current_site
from django.contrib import messages
from django.utils.translation import ugettext as _


from authentic2.idp.decorators import prevent_access_to_transient_users
from authentic2.idp.saml import saml2_endpoints
from authentic2.saml import models as saml_models
from authentic2.compat import get_user_model


from . import app_settings
from . import forms


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

    def get_form_kwargs(self, **kwargs):
        kwargs = super(EditProfile, self).get_form_kwargs(**kwargs)
        kwargs['prefix'] = 'edit-profile'
        return kwargs


edit_profile = prevent_access_to_transient_users(EditProfile.as_view())


def su(request, username, redirect_url='/'):
    '''To use this view add:

       url(r'^su/(?P<username>.*)/$', 'authentic2.views.su', {'redirect_url': '/'}),
    '''
    if request.user.is_superuser or request.session.get('has_superuser_power'):
        su_user = shortcuts.get_object_or_404(get_user_model(), username=username)
        if su_user.is_active:
            request.session[SESSION_KEY] = su_user.id
            request.session['has_superuser_power'] = True
            return http.HttpResponseRedirect(redirect_url)
    else:
        return http.HttpResponseRedirect('/')


class RedirectToHomepageView(RedirectView):
    url = app_settings.A2_HOMEPAGE_URL


redirect_to_homepage = RedirectToHomepageView.as_view()


class EmailChangeView(FormView):
    form_class = forms.EmailChangeForm
    template_name = 'profiles/email_change.html'
    subject_template = 'profiles/email_change_subject.txt'
    body_template = 'profiles/email_change_body.txt'
    success_url = '../..'

    def form_valid(self, form):
        email = form.cleaned_data['email']
        site = get_current_site(self.request)
        token = signing.dumps({
            'email': email,
            'site_pk': site.pk,
            'user_pk': self.request.user.pk,
        })
        link = '{0}?token={1}'.format(
                reverse('email-change-verify'),
                token)
        link = self.request.build_absolute_uri(link)
        ctx = {'email': email,
               'site': site,
               'user': self.request.user,
               'link': link
        }
        subject = render_to_string(self.subject_template, ctx).strip()
        body = render_to_string(self.body_template, ctx)

        mail.EmailMessage(subject=subject,
                body=body, to=[email]).send()
        messages.info(self.request,
                _('Your request for changing your email '
                  'is received. An email of validation '
                  'was sent to you. Pleas click on the '
                  'link contained inside.'))
        return super(EmailChangeView, self).form_valid(form)

email_change = EmailChangeView.as_view()

class EmailChangeVerifyView(TemplateView):
    def get(self, request, *args, **kwargs):
        if 'token' in request.GET:
            User = get_user_model()
            try:
                token = signing.loads(request.GET['token'], max_age=7200)
                user_pk = token['user_pk']
                email = token['email']
                site_pk = token['site_pk']
                site = get_current_site(request)
                if site.pk != site_pk:
                    raise ValueError
                user = User.objects.get(pk=user_pk)
                user.email = email
                user.save()
                messages.info(request, _('your request for changing your email '
                    'is successful'))
            except signing.SignatureExpired:
                messages.error(request, _('your request for changing your email is too '
                    'old, try again'))
            except signing.BadSignature:
                messages.error(request, _('your request for changing your email is '
                    'invalid, try again'))
            except ValueError:
                messages.error(request, _('your request for changing your email was not '
                    'on this site, try again'))
            except User.DoesNotExist:
                messages.error(request, _('your request for changing your email is for '
                    'an unknown user, try again'))
        return shortcuts.redirect(settings.LOGIN_REDIRECT_URL)

email_change_verify = EmailChangeVerifyView.as_view()
