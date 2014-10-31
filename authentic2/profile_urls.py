from django.conf.urls import patterns, url

urlpatterns = patterns('authentic2.views',
    url(r'^logged-in/$', 'logged_in', name='logged-in'),
    url(r'^edit/$', 'edit_profile', name='profile_edit'),
    url(r'^change-email/$', 'email_change', name='email-change'),
    url(r'^change-email/verify/$', 'email_change_verify',
        name='email-change-verify'),
    url(r'^$', 'profile', name='account_management'),
)
