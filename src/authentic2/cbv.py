from django.views.decorators.csrf import ensure_csrf_cookie, csrf_exempt

from django.utils.decorators import method_decorator
from django.forms import Form
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.conf import settings

from . import utils, hooks


class ValidateCSRFMixin(object):
    '''Move CSRF token validation inside the form validation.

       This mixin must always be the leftest one and if your class override
       form_valid() dispatch() you should move those overrides in a base
       class.
    '''
    @method_decorator(csrf_exempt)
    @method_decorator(ensure_csrf_cookie)
    def dispatch(self, *args, **kwargs):
        return super(ValidateCSRFMixin, self).dispatch(*args, **kwargs)

    def form_valid(self, *args, **kwargs):
        for form in args:
            if isinstance(form, Form):
                utils.csrf_token_check(self.request, form)
        if not form.is_valid():
            return self.form_invalid(form)
        return super(ValidateCSRFMixin, self).form_valid(*args, **kwargs)


class RedirectToNextURLViewMixin(object):
    def get_success_url(self):
        if REDIRECT_FIELD_NAME in self.request.GET:
            return self.request.GET[REDIRECT_FIELD_NAME]
        return settings.LOGIN_REDIRECT_URL


class NextURLViewMixin(RedirectToNextURLViewMixin):
    '''Make a view handle a next parameter, if it's not present it is
       automatically generated from the Referrer or from the value
       returned by the method get_next_url_default().
    '''
    next_url_default = '..'

    def get_next_url_default(self):
        return self.next_url_default

    def dispatch(self, request, *args, **kwargs):
        if REDIRECT_FIELD_NAME in request.GET:
            pass
        else:
            next_url = request.META.get('HTTP_REFERER') or \
                self.next_url_default
            return utils.redirect(request, request.path, keep_params=True,
                                  params={
                                      REDIRECT_FIELD_NAME: next_url,
                                  },
                                  status=303)
        return super(NextURLViewMixin, self).dispatch(request, *args,
                                                      **kwargs)


class TemplateNamesMixin(object):
    def get_template_names(self):
        if hasattr(self, 'template_names'):
            return self.template_names
        return super(TemplateNamesMixin, self).get_template_names()


class HookMixin(object):
    def get_form(self):
        form = super(HookMixin, self).get_form()
        hooks.call_hooks('front_modify_form', self, form)
        return form
