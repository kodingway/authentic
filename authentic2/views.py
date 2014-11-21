import logging
import lasso
import thread
import requests
import urllib
import re


from django.conf import settings
from django.shortcuts import render_to_response, render
from django.template import RequestContext
from django.template.loader import render_to_string
from django.views.generic.edit import UpdateView, FormView
from django.views.generic import RedirectView, TemplateView
from django.views.generic.base import View
from django.contrib.auth import SESSION_KEY
from django import http, shortcuts
from django.core import mail, signing
from django.core.urlresolvers import reverse
from django.contrib import messages
from django.utils.translation import ugettext as _
from django.utils.http import urlencode
from django.contrib.auth import logout as auth_logout
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.http import (HttpResponseRedirect, HttpResponseForbidden,
    HttpResponse)
from django.core.exceptions import PermissionDenied
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.cache import never_cache
from django.contrib.auth.decorators import login_required
from django.db.models import FieldDoesNotExist


# FIXME: this decorator has nothing to do with an idp, should be moved in the
# a2 package
# FIXME: this constant should be moved in the a2 package


from . import (utils, app_settings, forms, compat, decorators,
    constants, models)


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
    return render(request, template_name)


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
        if app_settings.PUSH_PROFILE_UPDATES:
            thread.start_new_thread(self.push_attributes, ())
        return super(EditProfile, self).form_valid(form)

    def get_form_kwargs(self, **kwargs):
        kwargs = super(EditProfile, self).get_form_kwargs(**kwargs)
        kwargs['prefix'] = 'edit-profile'
        return kwargs

edit_profile = decorators.setting_enabled('A2_PROFILE_CAN_EDIT_PROFILE')(
    decorators.prevent_access_to_transient_users(EditProfile.as_view()))


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
    success_url = '..'

    def get_form_kwargs(self):
        kwargs = super(EmailChangeView, self).get_form_kwargs()
        kwargs.update({
            'user': self.request.user,
        })
        return kwargs

    def form_valid(self, form):
        email = form.cleaned_data['email']
        token = signing.dumps({
            'email': email,
            'user_pk': self.request.user.pk,
        })
        link = '{0}?token={1}'.format(
                reverse('email-change-verify'),
                token)
        link = self.request.build_absolute_uri(link)
        ctx = {'email': email,
               'user': self.request.user,
               'link': link,
               'domain': self.request.get_host(),
        }
        subject = render_to_string(self.subject_template, ctx).strip()
        body = render_to_string(self.body_template, ctx)

        mail.EmailMessage(subject=subject, body=body, to=[email]).send()
        messages.info(self.request,
                _('Your request for changing your email '
                  'is received. An email of validation '
                  'was sent to you. Please click on the '
                  'link contained inside.'))
        return super(EmailChangeView, self).form_valid(form)

email_change = decorators.setting_enabled('A2_PROFILE_CAN_CHANGE_EMAIL')(
    decorators.prevent_access_to_transient_users((EmailChangeView.as_view())))

class EmailChangeVerifyView(TemplateView):
    def get(self, request, *args, **kwargs):
        if 'token' in request.GET:
            User = compat.get_user_model()
            try:
                token = signing.loads(request.GET['token'], max_age=7200)
                user_pk = token['user_pk']
                email = token['email']
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
            else:
                return shortcuts.redirect('account_management')
        return shortcuts.redirect('email-change')


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
    nonce = request.REQUEST.get(constants.NONCE_FIELD_NAME)

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
                if hasattr(frontend, 'login'):
                    continue
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
                for frontend in frontends if frontend.enabled() and not hasattr(frontend, 'login')]

    context_instance = RequestContext(request)
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
            render_to_string(d['backend'].template(), context,
                context_instance=context_instance)))
    for frontend in frontends:
        if not hasattr(frontend, 'login') or not frontend.enabled():
            continue
        response = frontend.login(request, context_instance=context_instance)
        if response.status_code != 200:
            return response
        rendered_forms.append((frontend.name(), response.content))

    request.session.set_test_cookie()

    return render_to_response(template_name, {
        'methods': rendered_forms,
        redirect_field_name: redirect_to,
    }, context_instance=context_instance)


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
    if not decorators.is_transient_user(request.user):
        tpl_parameters['account_management'] = 'account_management'
        tpl_parameters['authorized_services'] = service_list(request)
    return render_to_response('idp/homepage.html',
       tpl_parameters, RequestContext(request))

class ProfileView(TemplateView):
    template_name = 'idp/account_management.html'

    def get_context_data(self, **kwargs):
        ctx = super(ProfileView, self).get_context_data(**kwargs)
        frontends = utils.get_backends('AUTH_FRONTENDS')
        request = self.request

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
        field_names = app_settings.A2_PROFILE_FIELDS
        if not field_names:
            field_names = list(app_settings.A2_REGISTRATION_FIELDS)
            for field_name in getattr(request.user, 'USER_PROFILE', []):
                if field_name not in field_names:
                    field_names.append(field_name)
            qs = models.Attribute.objects.filter(user_visible=True)
            qs = qs.values_list('name', flat=True)
            for field_name in qs:
                if field_name not in field_names:
                    field_names.append(field_name)
        for field_name in field_names:
            title = None
            if isinstance(field_name, (list, tuple)):
                if len(field_name) > 1:
                    title = field_name[1]
                field_name = field_name[0]
            try:
                field = request.user._meta.get_field(field_name)
            except FieldDoesNotExist:
                qs = models.AttributeValue.objects.with_owner(request.user)
                qs = qs.filter( attribute__name=field_name, attribute__user_visible=True)
                qs = qs.select_related()
                value = [at_value.to_python() for at_value in qs]
                value = filter(None, value)
                if qs and not title:
                    title = unicode(qs[0].attribute)
            else:
                if not title:
                    title = field.verbose_name
                value = getattr(self.request.user, field_name, None)
            if not value:
                continue
            if callable(value):
                value = value()
            if not isinstance(value, (list, tuple)):
                value = (value,)
            profile.append((title, map(unicode, value)))
        # Credentials management
        blocks = [ frontend.profile(request) for frontend in frontends \
                if hasattr(frontend, 'profile') and frontend.enabled() ]
        idp_backends = utils.get_backends()
        # Get actions for federation management
        federation_management = []
        if app_settings.A2_PROFILE_CAN_MANAGE_FEDERATION:
            for idp_backend in idp_backends:
                if hasattr(idp_backend, 'federation_management'):
                    federation_management.extend(idp_backend.federation_management(request))
        ctx.update({
            'frontends_block': blocks,
            'profile': profile,
            'allow_account_deletion': app_settings.A2_REGISTRATION_CAN_DELETE_ACCOUNT,
            'allow_profile_edit': app_settings.A2_PROFILE_CAN_EDIT_PROFILE,
            'allow_email_change': app_settings.A2_PROFILE_CAN_CHANGE_EMAIL,
            'federation_management': federation_management,
        })
        return ctx

profile = decorators.prevent_access_to_transient_users(ProfileView.as_view())

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


def login_password_profile(request):
    can_change_password = (app_settings.A2_REGISTRATION_CAN_CHANGE_PASSWORD
                           and request.user.has_usable_password)
    return render_to_string('auth/login_password_profile.html',
                            {'can_change_password' : can_change_password},
                            RequestContext(request))


def redirect_to_login(request, next=None, nonce=None, keep_qs=False):
    '''Redirect to the login, eventually adding a nonce'''
    if next is None:
        if keep_qs:
            next = request.get_full_path()
        else:
            next = request.path
    qs = { REDIRECT_FIELD_NAME: next }
    if nonce is not None:
        qs.update({ constants.NONCE_FIELD_NAME: nonce })
    return HttpResponseRedirect('%s?%s' % (reverse('auth_login'), urlencode(qs)))



class LoggedInView(View):
    '''JSONP web service to detect if an user is logged'''
    http_method_names = [u'get']

    def check_referrer(self):
        '''Check if the given referer is authorized'''
        referer = self.request.META.get('HTTP_REFERER', '')
        for valid_referer in app_settings.VALID_REFERERS:
            if referer.startswith(valid_referer):
                return True
        return False

    def get(self, request, *args, **kwargs):
        if not self.check_referrer():
            return HttpResponseForbidden()
        callback = request.GET.get('callback')
        content = u'{0}({1})'.format(callback, int(request.user.is_authenticated()))
        return HttpResponse(content, content_type='application/json')

logged_in = never_cache(LoggedInView.as_view())
