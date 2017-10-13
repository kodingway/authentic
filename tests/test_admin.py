# -*- coding: utf-8 -*-

from urlparse import urlparse

from authentic2.custom_user.models import User
from authentic2.models import Attribute

import utils


def test_user_admin(db, app, superuser):
    utils.login(app, superuser)
    Attribute.objects.create(label='SIRET', name='siret', kind='string', required=False,
                             user_visible=True, user_editable=False, asked_on_registration=False,
                             multiple=False)
    Attribute.objects.create(label='Civilité', name='civilite', kind='title', required=False,
                             user_visible=True, user_editable=True, asked_on_registration=True,
                             multiple=False)
    resp = app.get('/admin/custom_user/user/%s/' % superuser.pk)
    assert set(resp.form.fields.keys()) >= set(['username', 'first_name', 'last_name', 'civilite',
                                                'siret', 'is_staff', 'is_superuser', 'ou', 'groups',
                                                'date_joined_0', 'date_joined_1', 'last_login_0',
                                                'last_login_1'])
    resp.form.set('first_name', 'John')
    resp.form.set('last_name', 'Doe')
    resp.form.set('civilite', 'Mr')
    resp.form.set('siret', '1234')
    resp = resp.form.submit('_continue').follow()
    modified_admin = User.objects.get(pk=superuser.pk)
    assert modified_admin.first_name == 'John'
    assert modified_admin.last_name == 'Doe'
    assert modified_admin.attributes.civilite == 'Mr'
    assert modified_admin.attributes.siret == '1234'


def test_app_setting_login_url(app, db, settings):
    settings.A2_MANAGER_LOGIN_URL = '/other-login/'
    response = app.get('/admin/')
    assert urlparse(response['Location']).path == '/admin/login/'
    response = response.follow()
    assert urlparse(response['Location']).path == settings.A2_MANAGER_LOGIN_URL
    assert urlparse(response['Location']).query == 'next=/admin/'
