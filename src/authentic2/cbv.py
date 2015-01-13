from django.views.decorators.csrf import ensure_csrf_cookie, csrf_exempt

from django.utils.decorators import method_decorator
from django.forms import Form

from . import utils

class ValidateCSRFMixin(object):
    '''Move CSRF token validation inside the form validation.

       This mixin must always be the leftest one and if your class override
       form_valid() or dispatch() you should move those overrides in a base
       class.
    '''
    @method_decorator(csrf_exempt)
    def dispatch(self, *args, **kwargs):
        return super(ValidateCSRFMixin, self).dispatch(*args, **kwargs)

    @method_decorator(ensure_csrf_cookie)
    def form_valid(self, *args, **kwargs):
        for form in args:
            if isinstance(form, Form):
                utils.csrf_token_check(self.request, form)
        if not form.is_valid():
            return self.form_invalid(form)
        return super(ValidateCSRFMixin, self).form_valid(*args, **kwargs)
