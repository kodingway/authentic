from django.conf.urls import patterns
from django.conf.urls import url

from django.views.generic.base import TemplateView
from django.contrib.auth.decorators import login_required

from .views import RegistrationView, registration_completion, DeleteView

urlpatterns = patterns('',
    url(r'^activate/(?P<registration_token>[\w: -]+)/$',
	registration_completion, name='registration_activate'),
    url(r'^register/$',
        RegistrationView.as_view(),
        name='registration_register'),
    url(r'^register/complete/$',
        TemplateView.as_view(template_name='registration/registration_complete.html'),
        name='registration_complete'),
    url(r'^register/closed/$',
        TemplateView.as_view(template_name='registration/registration_closed.html'),
        name='registration_disallowed'),
    url(r'^delete/$',
        login_required(DeleteView.as_view()),
        name='delete_account'),
)
