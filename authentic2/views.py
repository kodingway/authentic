import logging
import lasso
import thread
import requests
import urllib
import re


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
from django.contrib.auth import logout as auth_logout
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.contrib.auth.models import SiteProfileNotAvailable
from django.http import HttpResponseRedirect
from django.core.exceptions import ObjectDoesNotExist
from django.views.decorators.csrf import csrf_protect
from django.contrib.sites.models import Site, RequestSite
from django.views.decorators.cache import never_cache
from django.contrib.auth.decorators import login_required


# FIXME: this decorator has nothing to do with an idp, should be moved in the
# a2 package
# FIXME: this constant should be moved in the a2 package
from authentic2.auth2_auth import NONCE_FIELD_NAME


from . import utils, app_settings, forms, compat, decorators


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
    model = compat.get_user_model()
    form_class = forms.UserProfileForm
    template_name = 'profiles/edit_profile.html'
    success_url = '../'

    def get_object(self):
        return self.request.user

    def push_attributes(self):
        # FIXME: we should net refer to a specific idp module here
        from authentic2.idp.saml import saml2_endpoints
        from authentic2.saml import models as saml_models

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


edit_profile = decorators.prevent_access_to_transient_users(EditProfile.as_view())


def su(request, username, redirect_url='/'):
    '''To use this view add:

       url(r'^su/(?P<username>.*)/$', 'authentic2.views.su', {'redirect_url': '/'}),
    '''
    if request.user.is_superuser or request.session.get('has_superuser_power'):
        su_user = shortcuts.get_object_or_404(compat.get_user_model(), username=username)
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

    def get_form_kwargs(self):
        kwargs = super(EmailChangeView, self).get_form_kwargs()
        kwargs.update({
            'user': self.request.user,
        })
        return kwargs

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
                  'was sent to you. Please click on the '
                  'link contained inside.'))
        return super(EmailChangeView, self).form_valid(form)

email_change = decorators.prevent_access_to_transient_users(EmailChangeView.as_view())

class EmailChangeVerifyView(TemplateView):
    def get(self, request, *args, **kwargs):
        if 'token' in request.GET:
            User = compat.get_user_model()
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
                messages.info(request, _('your request for changing your email for {0} '
                    'is successful').format(email))
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

logger = logging.getLogger('authentic2.idp.views')

__logout_redirection_timeout = getattr(settings, 'IDP_LOGOUT_TIMEOUT', 600)

@csrf_protect
@never_cache
def login(request, template_name='auth/login.html',
          login_form_template='auth/login_form.html',
          redirect_field_name=REDIRECT_FIELD_NAME):
    """Displays the login form and handles the login action."""

    redirect_to = request.REQUEST.get(redirect_field_name)
    if not redirect_to or ' ' in redirect_to:
        redirect_to = settings.LOGIN_REDIRECT_URL
    # Heavier security check -- redirects to http://example.com should
    # not be allowed, but things like /view/?param=http://example.com
    # should be allowed. This regex checks if there is a '//' *before* a
    # question mark.
    elif '//' in redirect_to and re.match(r'[^\?]*//', redirect_to):
            redirect_to = settings.LOGIN_REDIRECT_URL
    nonce = request.REQUEST.get(NONCE_FIELD_NAME)

    frontends = utils.get_backends('AUTH_FRONTENDS')

    # If already logged, leave now
    if not request.user.is_staff \
            and not request.user.is_anonymous() \
            and nonce is None \
            and request.method != 'POST':
        return HttpResponseRedirect(redirect_to)

    if request.method == "POST":
        if 'cancel' in request.POST:
            redirect_to = utils.add_arg(redirect_to, 'cancel')
            return HttpResponseRedirect(redirect_to)
        else:
            forms = []
            for frontend in frontends:
                if not frontend.enabled():
                    continue
                if 'submit-%s' % frontend.id() in request.POST:
                    form = frontend.form()(data=request.POST)
                    if form.is_valid():
                        if request.session.test_cookie_worked():
                            request.session.delete_test_cookie()
                        return frontend.post(request, form, nonce, redirect_to)
                    forms.append((frontend.name(), {'form': form, 'backend': frontend}))
                else:
                    forms.append((frontend.name(), {'form': frontend.form()(), 'backend': frontend}))
    else:
        forms = [(frontend.name(), { 'form': frontend.form()(), 'backend': frontend }) \
                for frontend in frontends if frontend.enabled()]

    rendered_forms = []
    for name, d in forms:
        context = { 'cancel': nonce is not None,
                    'submit_name': 'submit-%s' % d['backend'].id(),
                    redirect_field_name: redirect_to,
                    'can_reset_password': app_settings.A2_CAN_RESET_PASSWORD,
                    'registration_authorized': getattr(settings, 'REGISTRATION_OPEN', True),
                    'form': d['form'] }
        if hasattr(d['backend'], 'get_context'):
            context.update(d['backend'].get_context())
        rendered_forms.append((name,
            render_to_string(d['backend'].template(),
                RequestContext(request, context))))

    request.session.set_test_cookie()

    if Site._meta.installed:
        current_site = Site.objects.get_current()
    else:
        current_site = RequestSite(request)

    return render_to_response(template_name, {
        'methods': rendered_forms,
        redirect_field_name: redirect_to,
        'site': current_site,
        'site_name': current_site.name,
    }, context_instance=RequestContext(request))


def service_list(request):
    '''Compute the service list to show on user homepage'''
    return utils.accumulate_from_backends(request, 'service_list')

def homepage(request):
    if app_settings.A2_HOMEPAGE_URL:
        return redirect_to_homepage(request)
    else:
        return _homepage(request)

@login_required
def _homepage(request):
    '''Homepage of the IdP'''
    tpl_parameters = {}
    # FIXME: we should not refer to a specific authentication module here
    from authentic2.authsaml2.models import SAML2TransientUser
    if not isinstance(request.user, SAML2TransientUser):
        tpl_parameters['account_management'] = 'account_management'
        tpl_parameters['authorized_services'] = service_list(request)
    return render_to_response('idp/homepage.html',
       tpl_parameters, RequestContext(request))

@decorators.prevent_access_to_transient_users
def profile(request):

    frontends = utils.get_backends('AUTH_FRONTENDS')

    if request.method == "POST":
        for frontend in frontends:
            if not frontend.enabled():
                continue
            if 'submit-%s' % frontend.id() in request.POST:
                form = frontend.form()(data=request.POST)
                if form.is_valid():
                    if request.session.test_cookie_worked():
                        request.session.delete_test_cookie()
                    return frontend.post(request, form, None, '/profile')
    # User attributes management
    profile = []
    try:
        for field_name in getattr(request.user, 'USER_PROFILE', []):
            if isinstance(field_name, tuple):
                field_name, title = field_name
            elif isinstance(field_name, str):
                title = request.user._meta.get_field(field_name).verbose_name
            else:
                raise TypeError('USER_PROFILE must contain string or tuple')
            value = getattr(request.user, field_name, None)
            if not value:
                continue
            if callable(value):
                value = value()
            if not isinstance(value, basestring) and hasattr(value, '__iter__'):
                profile.append((title, map(unicode, value)))
            else:
                profile.append((title, [unicode(value)]))
    except (SiteProfileNotAvailable, ObjectDoesNotExist):
        pass
    # Credentials management
    blocks = [ frontend.profile(request, next='/profile') for frontend in frontends \
            if hasattr(frontend, 'profile') ]
    return render_to_response('idp/account_management.html', {
        'frontends_block': blocks,
        'profile': profile,
        'allow_account_deletion': app_settings.A2_REGISTRATION_CAN_DELETE_ACCOUNT,
        },
        RequestContext(request))

def logout_list(request):
    '''Return logout links from idp backends'''
    return utils.accumulate_from_backends(request, 'logout_list')

def logout(request, next_page='/', redirect_field_name=REDIRECT_FIELD_NAME,
        template = 'idp/logout.html'):
    global __logout_redirection_timeout
    "Logs out the user and displays 'You are logged out' message."
    do_local = 'local' in request.REQUEST
    context = RequestContext(request)
    context['redir_timeout'] = __logout_redirection_timeout
    next_page = request.REQUEST.get(redirect_field_name, next_page)
    if not do_local:
        l = logout_list(request)
        if l:
            # Full logout
            next_page = '/logout?local=ok&next=%s' % urllib.quote(next_page)
            context['logout_list'] = l
            logger.debug('logout: %r' % unicode(context['logout_list']))
            context['next_page'] = next_page
            context['message'] = _('Logging out from all your services')
            return render_to_response(template, context_instance = context)
    # Local logout
    auth_logout(request)
    context['next_page'] = next_page
    context['message'] = _('Logged out')
    return render_to_response(template, context_instance = context)

def redirect_to_logout(request, next_page='/'):
    return HttpResponseRedirect('%s?next=%s' % (reverse(logout), urllib.quote(next_page)))
