from django.utils.translation import ugettext as _
from django.core.urlresolvers import reverse
from django.views.generic import DeleteView, View
from django.http import HttpResponseRedirect

from django.contrib.auth import REDIRECT_FIELD_NAME
from django.contrib import messages

from authentic2.saml.models import LibertyFederation

class FederationCreateView(View):
    pass

class FederationDeleteView(DeleteView):
    model = LibertyFederation

    def get_queryset(self):
        # check current user owns this federation
        qs = super(FederationDeleteView, self).get_queryset()
        return qs.filter(user=self.request.user)

    def delete(self, request, *args, **kwargs):
        self.object = self.get_object()
        self.object.user = None
        self.object.save()
        messages.info(request, _('Federation to {0} deleted').format(
            self.object.sp.liberty_provider.name))
        return HttpResponseRedirect(self.get_success_url())

    def get_success_url(self):
        return self.request.POST.get(REDIRECT_FIELD_NAME,
                reverse('auth_homepage'))


delete_federation = FederationDeleteView.as_view()
create_federation = FederationCreateView.as_view()
