from django.utils.translation import gettext_noop
from django.template.loader import render_to_string
from django.template import RequestContext
from django.shortcuts import render
from mellon.utils import get_idp, get_idps

from authentic2.utils import redirect_to_login

from . import app_settings


class SAMLFrontend(object):
    id = 'saml'

    def enabled(self):
        return app_settings.enable and list(get_idps())

    def name(self):
        return gettext_noop('SAML')

    def login(self, request, *args, **kwargs):
        context_instance = kwargs.pop('context_instance', None) or RequestContext(request)
        submit_name = 'login-%s' % self.id
        if request.method == 'POST' and submit_name in request.POST:
            return redirect_to_login(request, login_url='mellon_login')
        return render(request, 'authentic2_auth_saml/login.html', {'submit_name': submit_name},
                      context_instance=context_instance)

    def profile(self, request, *args, **kwargs):
        context_instance = kwargs.pop('context_instance', None) or RequestContext(request)
        user_saml_identifiers = request.user.saml_identifiers.all()
        if not user_saml_identifiers:
            return ''
        for user_saml_identifier in user_saml_identifiers:
            user_saml_identifier.idp = get_idp(user_saml_identifier.issuer)
        return render_to_string('authentic2_auth_saml/profile.html',
                                {'user_saml_identifiers': user_saml_identifiers},
                                context_instance=context_instance)
