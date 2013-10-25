from django.core.urlresolvers import reverse
from django.views.generic import FormView

from .forms import AddLibertyProviderFromUrlForm

class AdminAddFormViewMixin(object):
    model_admin = None

    def get_context_data(self, **kwargs):
        ctx = super(AdminAddFormViewMixin, self).get_context_data(**kwargs)
        ctx.update({
            'app_label': self.model_admin.model._meta.app_label,
            'has_change_permission': self.model_admin.has_change_permission(self.request),
            'opts': self.model_admin.model._meta })
        return ctx

class AddLibertyProviderFromUrlView(AdminAddFormViewMixin, FormView):
    form_class = AddLibertyProviderFromUrlForm
    template_name = 'admin/saml/libertyprovider/add_from_url.html'

    def form_valid(self, form):
        form.save()
        self.success_url = reverse(
                'admin:saml_libertyprovider_change',
                args=(form.instance.id,))
        return super(AddLibertyProviderFromUrlView, self).form_valid(form)
