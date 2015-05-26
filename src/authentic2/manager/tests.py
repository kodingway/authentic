# -*- coding: utf-8 -*-
import re

from django.contrib.auth import get_user_model
from django_rbac.utils import get_role_model, get_ou_model 
from django_rbac.models import VIEW_OP
from django.test import Client
from django.core import mail

from lxml import html

from authentic2.tests import Authentic2TestCase as TestCase
from authentic2.models import Service

User = get_user_model()
Role = get_role_model()
OU = get_ou_model()


class ManagerRBACTestCase(TestCase):
    def setUp(self):
        self.ou1 = OU.objects.create(name='ou1')
        self.ou2 = OU.objects.create(name='ou2')
        self.ou1_u1 = User.objects.create(username='ou1_u1', ou=self.ou1)
        self.ou1_u1.set_password('u1')
        self.ou1_u1.save()
        self.ou1_u2 = User.objects.create(username='ou1_u2', ou=self.ou1)
        self.ou1_u2.set_password('u2')
        self.ou1_u2.save()
        self.ou2_u1 = User.objects.create(username='ou2_u1', ou=self.ou2)
        self.ou2_u1.set_password('u1')
        self.ou2_u1.save()
        self.ou2_u2 = User.objects.create(username='ou2_u2', ou=self.ou2)
        self.ou2_u2.set_password('u2')
        self.ou2_u2.save()
        self.ou1_admin_role = Role.objects.get_admin_role(self.ou1, 'admin '
                                                          'ou1', 'admin-ou1',
                                                          operation=VIEW_OP)
        self.ou1_admin_role.members.add(self.ou1_u1)
        self.ou2_admin_role = Role.objects.get_admin_role(self.ou2, 'admin '
                                                          'ou2', 'admin-ou2',
                                                         operation=VIEW_OP)
        self.ou2_admin_role.members.add(self.ou2_u1)
        self.ou2_admin_role.members.add(self.ou1_u1)

    def test_ou1_u1_access(self):
        client = Client()
        client.login(username='ou1_u1', password='u1')
        response = client.get('/')
        self.assertEqual(response.status_code, 200)
        response = client.get('/manage/')
        self.assertEqual(response.status_code, 200)
        doc = html.fromstring(response.content)
        nodes = doc.cssselect('ul.apps > li')
        self.assertEqual(len(nodes), 4)
        self.assertEqual(set(node.get('id') for node in nodes),
                         set(['organizational-units', 'users', 'roles', 'services']))
        response = client.get('/manage/users/')
        self.assertEqual(response.status_code, 200)
        doc = html.fromstring(response.content)
        nodes = doc.cssselect('table td.username')
        self.assertEqual(set(node.text for node in nodes),
                         set(['ou1_u1', 'ou1_u2', 'ou2_u1', 'ou2_u2']))
        response = client.get('/manage/roles/')
        self.assertEqual(response.status_code, 200)
        doc = html.fromstring(response.content)
        nodes = doc.cssselect('table td.ou')
        self.assertEqual(set(node.text for node in nodes),
                         set(['ou1', 'ou2', u'\u2014']))

    def test_ou1_u2_access(self):
        client = Client()
        client.login(username='ou1_u2', password='u2')
        response = client.get('/')
        self.assertEqual(response.status_code, 200)
        response = client.get('/manage/')
        self.assertEqual(response.status_code, 403)
        response = client.get('/manage/users/')
        self.assertEqual(response.status_code, 403)
        response = client.get('/manage/roles/')
        self.assertEqual(response.status_code, 403)

    def test_ou2_u1_access(self):
        client = Client()
        client.login(username='ou2_u1', password='u1')
        response = client.get('/')
        self.assertEqual(response.status_code, 200)
        response = client.get('/manage/')
        self.assertEqual(response.status_code, 200)
        doc = html.fromstring(response.content)
        nodes = doc.cssselect('ul.apps > li')
        self.assertEqual(len(nodes), 4)
        self.assertEqual(set(node.get('id') for node in nodes),
                         set(['organizational-units', 'users', 'roles', 'services']))
        response = client.get('/manage/users/')
        self.assertEqual(response.status_code, 200)
        doc = html.fromstring(response.content)
        nodes = doc.cssselect('table td.username')
        self.assertEqual(set(node.text for node in nodes),
                         set(['ou2_u1', 'ou2_u2']))
        response = client.get('/manage/roles/')
        self.assertEqual(response.status_code, 200)
        doc = html.fromstring(response.content)
        nodes = doc.cssselect('table td.ou')
        self.assertEqual(set(node.text for node in nodes), set(['ou2', u'\u2014']))

    def test_ou2_u1_role_add(self):
        client = Client()
        client.login(username='ou2_u1', password='u1')
        response = client.get('/manage/roles/add/')
        self.assertEqual(response.status_code, 200)
        response = client.post('/manage/roles/add/', {'name': 'Service petite enfance',
                                                      'slug': 'service-petite-enfance',
                                                      'ou': str(self.ou1.pk) })
        doc = html.fromstring(response.content)
        self.assertEqual(len(doc.cssselect('p.error select#id_ou')), 1,
                         'adding role in ou1 should fail')
        response = client.post('/manage/roles/add/', {'name': 'Service petite enfance',
                                                      'slug': 'service-petite-enfance',
                                                      'ou': str(self.ou2.pk) })
        self.assertEqual(response.status_code, 302)
        self.assertTrue(re.match('http://testserver/manage/roles/\d+/', response['Location']))

    def test_ou2_u1_user_add(self):
        client = Client()
        client.login(username='ou2_u1', password='u1')
        response = client.get('/manage/users/add/')
        self.assertEqual(response.status_code, 200)
        response = client.post('/manage/users/add/', {'username': 'Service petite enfance',
                                                      'password1': 'coin',
                                                      'password2': 'coin',
                                                      'send_mail': '1',
                                                      'ou': str(self.ou1.pk) })
        doc = html.fromstring(response.content)
        self.assertEqual(len(doc.cssselect('p.error select#id_ou')), 1,
                         'adding role in ou1 should fail')
        self.assertEqual(len(mail.outbox), 0)
        response = client.post('/manage/users/add/', {'username': 'Service petite enfance',
                                                      'password1': 'coin',
                                                      'password2': 'coin',
                                                      'send_mail': 'on',
                                                      'ou': str(self.ou2.pk) })
        self.assertEqual(response.status_code, 302)
        self.assertEqual(len(mail.outbox), 1)
