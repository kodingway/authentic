# -*- coding: utf-8 -*-
import re

from authentic2.custom_user.models import User
from authentic2.models import Attribute


def test_string(db, app, admin, mailoutbox):
    Attribute.objects.create(name='nom_de_naissance', label='Nom de naissance', kind='string',
                             asked_on_registration=True)
    qs = User.objects.filter(first_name='John')

    response = app.get('/accounts/register/')
    form = response.form
    form.set('email', 'john.doe@example.com')
    response = form.submit().follow()
    assert 'john.doe@example.com' in response
    url = re.search('https?://[^\n ]*', mailoutbox[0].body).group()
    response = app.get(url)

    form = response.form
    assert response.pyquery('#id_nom_de_naissance').attr('maxlength') == '256'
    form.set('first_name', 'John')
    form.set('last_name', 'Doe')
    form.set('nom_de_naissance', '1234567890' * 30)
    form.set('password1', '12345abcd#')
    form.set('password2', '12345abcd#')
    response = form.submit()
    assert response.pyquery.find('.form-field-error #id_nom_de_naissance')

    form = response.form
    form.set('nom_de_naissance', u'Noël')
    form.set('password1', '12345abcd#')
    form.set('password2', '12345abcd#')
    response = form.submit().follow()
    assert qs.get().attributes.nom_de_naissance == u'Noël'
    qs.delete()

    app.authorization = ('Basic', (admin.username, admin.username))
    payload = {
        'first_name': 'John',
        'last_name': 'Doe',
        'nom_de_naissance': '1234567890' * 30,
    }
    app.post_json('/api/users/', params=payload, status=400)

    payload = {
        'first_name': 'John',
        'last_name': 'Doe',
        'nom_de_naissance': u'Noël',
    }
    app.post_json('/api/users/', params=payload, status=201)
    assert qs.get().attributes.nom_de_naissance == u'Noël'
    qs.delete()


def test_fr_postcode(db, app, admin, mailoutbox):
    Attribute.objects.create(name='postcode', label='postcode', kind='fr_postcode',
                             asked_on_registration=True)
    qs = User.objects.filter(first_name='John')

    response = app.get('/accounts/register/')
    form = response.form
    form.set('email', 'john.doe@example.com')
    response = form.submit().follow()
    assert 'john.doe@example.com' in response
    url = re.search('https?://[^\n ]*', mailoutbox[0].body).group()
    response = app.get(url)

    form = response.form
    form.set('first_name', 'John')
    form.set('last_name', 'Doe')
    form.set('postcode', 'abc')
    form.set('password1', '12345abcd#')
    form.set('password2', '12345abcd#')
    response = form.submit()
    assert response.pyquery.find('.form-field-error #id_postcode')

    form = response.form
    form.set('postcode', '123')
    form.set('password1', '12345abcd#')
    form.set('password2', '12345abcd#')
    response = form.submit()
    assert response.pyquery.find('.form-field-error #id_postcode')

    form = response.form
    form.set('postcode', '12345')
    form.set('password1', '12345abcd#')
    form.set('password2', '12345abcd#')
    response = form.submit().follow()
    assert qs.get().attributes.postcode == '12345'
    qs.delete()

    response = app.get(url)
    form = response.form
    form.set('first_name', 'John')
    form.set('last_name', 'Doe')
    form.set('postcode', ' 12345 ')
    form.set('password1', '12345abcd#')
    form.set('password2', '12345abcd#')
    response = form.submit().follow()
    assert qs.get().attributes.postcode == '12345'
    qs.delete()

    response = app.get(url)
    form = response.form
    form.set('first_name', 'John')
    form.set('last_name', 'Doe')
    form.set('postcode', '')
    form.set('password1', '12345abcd#')
    form.set('password2', '12345abcd#')
    response = form.submit().follow()
    assert qs.get().attributes.postcode == ''
    qs.delete()

    app.authorization = ('Basic', (admin.username, admin.username))

    payload = {
        'first_name': 'John',
        'last_name': 'Doe',
        'postcode': ' 1234abc ',
    }
    app.post_json('/api/users/', params=payload, status=400)

    payload = {
        'first_name': 'John',
        'last_name': 'Doe',
        'postcode': '1234',
    }
    app.post_json('/api/users/', params=payload, status=400)

    payload = {
        'first_name': 'John',
        'last_name': 'Doe',
        'postcode': '12345',
    }
    app.post_json('/api/users/', params=payload)
    assert qs.get().attributes.postcode == '12345'
    qs.delete()

    payload = {
        'first_name': 'John',
        'last_name': 'Doe',
        'postcode': None,
    }
    app.post_json('/api/users/', params=payload)
    assert qs.get().attributes.postcode is None
    qs.delete()

    payload = {
        'first_name': 'John',
        'last_name': 'Doe',
        'postcode': '',
    }
    app.post_json('/api/users/', params=payload)
    assert qs.get().attributes.postcode == ''
    qs.delete()


def test_phone_number(db, app, admin, mailoutbox):
    Attribute.objects.create(name='phone_number', label='phone', kind='phone_number',
                             asked_on_registration=True)
    qs = User.objects.filter(first_name='John')

    response = app.get('/accounts/register/')
    form = response.form
    form.set('email', 'john.doe@example.com')
    response = form.submit().follow()
    assert 'john.doe@example.com' in response
    url = re.search('https?://[^\n ]*', mailoutbox[0].body).group()
    response = app.get(url)

    form = response.form
    form.set('first_name', 'John')
    form.set('last_name', 'Doe')
    form.set('phone_number', 'abc')
    form.set('password1', '12345abcd#')
    form.set('password2', '12345abcd#')
    response = form.submit()
    assert response.pyquery.find('.form-field-error #id_phone_number')

    form = response.form
    assert response.pyquery('#id_phone_number').attr('maxlength') == '30'
    form.set('phone_number', '1234512345' * 10)
    form.set('password1', '12345abcd#')
    form.set('password2', '12345abcd#')
    response = form.submit()
    assert response.pyquery.find('.form-field-error #id_phone_number')

    form = response.form
    form.set('phone_number', '12345')
    form.set('password1', '12345abcd#')
    form.set('password2', '12345abcd#')
    response = form.submit().follow()
    assert qs.get().attributes.phone_number == '12345'
    qs.delete()

    response = app.get(url)
    form = response.form
    form.set('first_name', 'John')
    form.set('last_name', 'Doe')
    form.set('phone_number', '+12345')
    form.set('password1', '12345abcd#')
    form.set('password2', '12345abcd#')
    response = form.submit().follow()
    assert qs.get().attributes.phone_number == '+12345'
    qs.delete()

    response = app.get(url)
    form = response.form
    form.set('first_name', 'John')
    form.set('last_name', 'Doe')
    form.set('phone_number', '')
    form.set('password1', '12345abcd#')
    form.set('password2', '12345abcd#')
    response = form.submit().follow()
    assert qs.get().attributes.phone_number == ''
    qs.delete()

    response = app.get(url)
    form = response.form
    form.set('first_name', 'John')
    form.set('last_name', 'Doe')
    form.set('phone_number', ' +  1.2-3  4 5 ')
    form.set('password1', '12345abcd#')
    form.set('password2', '12345abcd#')
    response = form.submit().follow()
    assert qs.get().attributes.phone_number == '+12345'
    qs.delete()

    app.authorization = ('Basic', (admin.username, admin.username))

    payload = {
        'first_name': 'John',
        'last_name': 'Doe',
        'phone_number': 'abc',
    }
    app.post_json('/api/users/', params=payload, status=400)

    payload = {
        'first_name': 'John',
        'last_name': 'Doe',
        'phone_number': ' + 1 2 3 4 5 ',
    }
    app.post_json('/api/users/', params=payload, status=400)

    payload = {
        'first_name': 'John',
        'last_name': 'Doe',
        'phone_number': '12345',
    }
    app.post_json('/api/users/', params=payload)
    assert qs.get().attributes.phone_number == '12345'
    qs.delete()

    payload = {
        'first_name': 'John',
        'last_name': 'Doe',
        'phone_number': '+12345',
    }
    app.post_json('/api/users/', params=payload)
    assert qs.get().attributes.phone_number == '+12345'
    qs.delete()

    payload = {
        'first_name': 'John',
        'last_name': 'Doe',
        'phone_number': None,
    }
    app.post_json('/api/users/', params=payload)
    assert qs.get().attributes.phone_number is None
    qs.delete()

    payload = {
        'first_name': 'John',
        'last_name': 'Doe',
        'phone_number': '',
    }
    app.post_json('/api/users/', params=payload)
    assert qs.get().attributes.phone_number == ''
    qs.delete()
