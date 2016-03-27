import logging
from authentic2.compat_lasso import lasso
import thread
import requests
import urllib
import re
import collections


import django
from django.conf import settings
from django.shortcuts import render_to_response, render
from django.template import RequestContext
from django.template.loader import render_to_string, select_template
from django.views.generic.edit import UpdateView, FormView
from django.views.generic import RedirectView, TemplateView
from django.views.generic.base import View
from django.contrib.auth import SESSION_KEY
from django import http, shortcuts
from django.core import mail, signing
from django.core.urlresolvers import reverse
from django.contrib import messages
from django.utils.translation import ugettext as _
from django.utils.http import urlencode, same_origin
from django.contrib.auth import logout as auth_logout
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.http import (HttpResponseRedirect, HttpResponseForbidden,
    HttpResponse)
from django.core.exceptions import PermissionDenied
from django.views.decorators.csrf import csrf_exempt, ensure_csrf_cookie
from django.views.decorators.cache import never_cache
from django.contrib.auth.decorators import login_required
from django.db.models.fields import FieldDoesNotExist
from django.db.models.query import Q


# FIXME: this decorator has nothing to do with an idp, should be moved in the
# a2 package
# FIXME: this constant should be moved in the a2 package


from . import (utils, app_settings, forms, compat, decorators,
    constants, models, cbv)


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


class EditProfile(cbv.TemplateNamesMixin, UpdateView):
    model = compat.get_user_model()
    template_names = ['profiles/edit_profile.html',
                      'authentic2/accounts_edit.html']
    success_url = '../'

    @classmethod
    def can_edit_profile(cls):
        fields, labels = cls.get_fields()
        return bool(fields) and app_settings.A2_PROFILE_CAN_EDIT_PROFILE

    @classmethod
    def get_fields(cls):
        default_fields = list(models.Attribute.objects.filter(user_editable=True).values_list('name', flat=True))
        return utils.get_fields_and_labels(
            app_settings.A2_PROFILE_FIELDS,
            default_fields)

    def get_form_class(self):
        fields, labels = self.get_fields()
        return forms.modelform_factory(compat.get_user_model(),
                fields=fields, labels=labels)

    def get_object(self):
        return self.request.user

    def get_form_kwargs(self, **kwargs):
        kwargs = super(EditProfile, self).get_form_kwargs(**kwargs)
        kwargs['prefix'] = 'edit-profile'
        return kwargs

edit_profile = decorators.setting_enabled('A2_PROFILE_CAN_EDIT_PROFILE')(
    login_required(EditProfile.as_view()))


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


class EmailChangeView(cbv.TemplateNamesMixin, FormView):
    form_class = forms.EmailChangeForm
    template_names = [
        'profiles/email_change.html',
        'authentic2//change_email.html'
    ]
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
               'old_email': self.request.user.email,
               'user': self.request.user,
               'link': link,
               'domain': self.request.get_host(),
        }

        utils.send_templated_mail(
                email,
                ['authentic2/change_email_notification'],
                context=ctx,
                legacy_subject_templates=['profiles/email_change_subject.txt'],
                legacy_body_templates=['profiles/email_change_body.txt'])

        messages.info(self.request,
                _('Your request for changing your email '
                  'is received. An email of validation '
                  'was sent to you. Please click on the '
                  'link contained inside.'))
        logging.getLogger(__name__).info('email change request by %s',
                                         self.request.user)
        return super(EmailChangeView, self).form_valid(form)

email_change = decorators.setting_enabled('A2_PROFILE_CAN_CHANGE_EMAIL')(
    login_required(EmailChangeView.as_view()))

class EmailChangeVerifyView(TemplateView):
    def get(self, request, *args, **kwargs):
        if 'token' in request.GET:
            User = compat.get_user_model()
            try:
                token = signing.loads(request.GET['token'], max_age=7200)
                user_pk = token['user_pk']
                email = token['email']
                user = User.objects.get(pk=user_pk)
                old_email = user.email
                user.email = email
                user.save()
                messages.info(request, _('your request for changing your email for {0} '
                    'is successful').format(email))
                logging.getLogger(__name__).info('user %s changed its email '
                                                 'from %s to %s', user,
                                                 old_email, email)
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

@csrf_exempt
@ensure_csrf_cookie
@never_cache
def login(request, template_name='authentic2/login.html',
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

    # set default priority and name
    for frontend in frontends:
        if not hasattr(frontend, 'name'):
            frontend.name = frontend.name()
        if not hasattr(frontend, 'priority'):
            frontend.priority = 0

    blocks = []

    context_instance = RequestContext(request, {
        'cancel': nonce is not None,
        'can_reset_password': app_settings.A2_CAN_RESET_PASSWORD,
        'registration_authorized': getattr(settings, 'REGISTRATION_OPEN', True),
    })
    if django.VERSION >= (1, 8, 0):
        context_instance['add_to_blocks'] = collections.defaultdict(lambda: [])

    # Cancel button
    if request.method == "POST" \
            and constants.CANCEL_FIELD_NAME in request.POST:
        return utils.continue_to_next_url(request, params={'cancel': 1})

    # Create blocks
    for frontend in frontends:
        if not frontend.enabled():
            continue
        # Legacy API
        if not hasattr(frontend, 'login'):
            fid = frontend.id()
            name = frontend.name
            form_class = frontend.form()
            submit_name = 'submit-%s' % fid
            block = {
                    'id': fid,
                    'name': name,
                    'frontend': frontend
            }
            if request.method == 'POST' and submit_name in request.POST:
                form = form_class(data=request.POST)
                if form.is_valid():
                    if request.session.test_cookie_worked():
                        request.session.delete_test_cookie()
                    return frontend.post(request, form, nonce, redirect_to)
                block['form'] = form
            else:
                block['form'] = form_class()
            blocks.append(block)
        else: # New frontends API
            response = frontend.login(request,
                                      context_instance=context_instance)
            if not response:
                continue
            if response.status_code != 200:
                return response
            blocks.append({
                    'id': frontend.id(),
                    'name': frontend.name,
                    'content': response.content,
                    'frontend': frontend,
            })
        if hasattr(frontend, 'is_hidden'):
            blocks[-1]['is_hidden'] = frontend.is_hidden(request)
        else:
            blocks[-1]['is_hidden'] = False


    # Old frontends API
    for block in blocks:
        fid = block['id']
        if not 'form' in block:
            continue
        frontend = block['frontend']
        context = {
                'submit_name': 'submit-%s' % fid,
                redirect_field_name: redirect_to,
                'form': block['form']
        }
        if hasattr(frontend, 'get_context'):
            context.update(frontend.get_context())
        sub_template_name = frontend.template()
        block['content'] = render_to_string(
                sub_template_name, context,
                context_instance=context_instance)

    request.session.set_test_cookie()

    # order blocks by their frontend priority
    blocks.sort(key=lambda block: block['frontend'].priority)

    # legacy context variable
    rendered_forms = [(block['name'], block['content']) for block in blocks]

    return render_to_response(template_name, {
        'methods': rendered_forms,
        # new definition
        'blocks': collections.OrderedDict((block['id'], block) for block in blocks),
        redirect_field_name: redirect_to,
    }, context_instance=context_instance)


def service_list(request):
    '''Compute the service list to show on user homepage'''
    return utils.accumulate_from_backends(request, 'service_list')

def homepage(request):
    if app_settings.A2_HOMEPAGE_URL:
        return utils.redirect(request, app_settings.A2_HOMEPAGE_URL)
    else:
        return _homepage(request)

@login_required
def _homepage(request):
    '''Homepage of the IdP'''
    tpl_parameters = {}
    tpl_parameters['account_management'] = 'account_management'
    tpl_parameters['authorized_services'] = service_list(request)
    return render_to_response(('idp/homepage.html',
                               'authentic2/homepage.html'), tpl_parameters,
                              RequestContext(request))

class ProfileView(cbv.TemplateNamesMixin, TemplateView):
    template_names = ['idp/account_management.html', 'authentic2/accounts.html']

    def get_context_data(self, **kwargs):
        ctx = super(ProfileView, self).get_context_data(**kwargs)
        frontends = utils.get_backends('AUTH_FRONTENDS')
        request = self.request

        context_instance = RequestContext(request, ctx)
        if django.VERSION >= (1, 8, 0):
            context_instance['add_to_blocks'] = collections.defaultdict(lambda: [])
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
            qs = models.Attribute.objects.filter(Q(user_editable=True)|Q(user_visible=True))
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
        blocks = [ frontend.profile(request, context_instance=context_instance) for frontend in frontends \
                if hasattr(frontend, 'profile') and frontend.enabled() ]
        blocks_by_id = {}
        for frontend in frontends:
            if hasattr(frontend, 'profile') and frontend.enabled():
                blocks_by_id[frontend.id()] = \
                    {'name': frontend.name(),
                     'content': frontend.profile(request, context_instance=context_instance)}
        idp_backends = utils.get_backends()
        # Get actions for federation management
        federation_management = []
        if app_settings.A2_PROFILE_CAN_MANAGE_FEDERATION:
            for idp_backend in idp_backends:
                if hasattr(idp_backend, 'federation_management'):
                    federation_management.extend(idp_backend.federation_management(request))
        context_instance.update({
            'frontends_block': blocks,
            'frontends_block_by_id': blocks_by_id,
            'profile': profile,
            'allow_account_deletion': app_settings.A2_REGISTRATION_CAN_DELETE_ACCOUNT,
            'allow_profile_edit': EditProfile.can_edit_profile(),
            'allow_email_change': app_settings.A2_PROFILE_CAN_CHANGE_EMAIL,
            'federation_management': federation_management,
        })
        return context_instance

profile = login_required(ProfileView.as_view())

def logout_list(request):
    '''Return logout links from idp backends'''
    return utils.accumulate_from_backends(request, 'logout_list')

def redirect_logout_list(request):
    '''Return redirect logout links from idp backends'''
    return utils.accumulate_from_backends(request, 'redirect_logout_list')

def logout(request, next_url=None, default_next_url='auth_homepage',
        redirect_field_name=REDIRECT_FIELD_NAME,
        template='authentic2/logout.html', do_local=True, check_referer=True):
    '''Logout first check if a logout request is authorized, i.e.
       that logout was done using a POST with CSRF token or with a GET
       from the same site.

       Logout endpoints of IdP module must re-user the view by setting
       check_referer and do_local to False.
    '''
    logger = logging.getLogger(__name__)
    default_next_url = utils.make_url(default_next_url)
    next_url = next_url or request.REQUEST.get(redirect_field_name,
            default_next_url)
    ctx = {}
    ctx['next_url'] = next_url
    ctx['redir_timeout'] = 60
    local_logout_done = False
    if request.user.is_authenticated():
        if check_referer and not utils.check_referer(request):
            return render(request, 'authentic2/logout_confirm.html', ctx)
        do_local = do_local and 'local' in request.REQUEST
        if not do_local:
            l = logout_list(request)
            if l:
                # Full logout with iframes
                next_url = utils.make_url('auth_logout', params={
                    'local': 'ok',
                    REDIRECT_FIELD_NAME: next_url})
                ctx['next_url'] = next_url
                ctx['logout_list'] = l
                ctx['message'] = _('Logging out from all your services')
                return render(request, template, ctx)
        # Get redirection targets for full logout with redirections
        # (needed before local logout)
        targets = redirect_logout_list(request)
        logger.debug('Accumulated redirections : {}'.format(targets))
        # Local logout
        auth_logout(request)
        logger.info('Logged out')
        local_logout_done = True
        # Last redirection will be the current next_url
        targets.append(next_url)
        # Put redirection targets in session (after local logout)
        request.session['logout_redirections'] = targets
        logger.debug('All planned redirections : {}'.format(targets))
    # Full logout by redirections if any
    targets = request.session.pop('logout_redirections', None)
    if targets:
        # Full logout with redirections
        logger.debug('Redirections queue: {}'.format(targets))
        next_url = targets.pop(0)
        request.session['logout_redirections'] = targets
    logger.debug('Next redirection : {}'.format(next_url))
    response = utils.redirect(request, next_url)
    if local_logout_done:
        response.set_cookie('a2_just_logged_out', 1, max_age=60)
        messages.info(request, _('You have been logged out'))
    return response


def login_password_profile(request, *args, **kwargs):
    context_instance = kwargs.pop('context_instance', None) or RequestContext(request)
    can_change_password = (app_settings.A2_REGISTRATION_CAN_CHANGE_PASSWORD
                           and request.user.has_usable_password())
    return render_to_string(['auth/login_password_profile.html',
                             'authentic2/login_password_profile.html'],
                            {'can_change_password' : can_change_password},
                            context_instance=context_instance)


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

def csrf_failure_view(request, reason=""):
    messages.warning(request, _('The page is out of date, it was reloaded for you'))
    return HttpResponseRedirect(request.get_full_path())

def test_redirect(request):
    next_url = request.GET.get(REDIRECT_FIELD_NAME, settings.LOGIN_REDIRECT_URL)
    messages.info(request, 'Une info')
    messages.warning(request, 'Un warning')
    messages.error(request, 'Une erreur')
    return HttpResponseRedirect(next_url)
