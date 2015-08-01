from django.test import TestCase
from django.contrib.contenttypes.models import ContentType
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError

from django_rbac.utils import get_permission_model, get_role_model

Permission = get_permission_model()
Role = get_role_model()
User = get_user_model()


class CustomUserTestCase(TestCase):
    def test_roles_and_parents(self):
        rchild1 = Role.objects.create(name='role-child1')
        rparent1 = Role.objects.create(name='role-parent1')
        rparent2 = Role.objects.create(name='role-parent2')
        rchild2 = Role.objects.create(name='role-child2')
        rparent1.add_child(rchild1)
        rparent1.add_child(rchild2)
        rparent2.add_child(rchild1)
        rparent2.add_child(rchild2)

        user1 = User.objects.create(username='user')
        user1.roles.add(rchild1)
        self.assertEqual(set([r.id for r in user1.roles_and_parents()]),
                         set([rchild1.id, rparent1.id, rparent2.id]))
        for r in user1.roles_and_parents():
            if r.id == rchild1.id:
                self.assertEqual(r.member, [user1])
            else:
                self.assertIn(r.id, [rparent1.id, rparent2.id])
                self.assertEqual(r.member, [])
        user1.roles.remove(rchild1)
        user1.roles.add(rchild2)
        self.assertEqual(set([r.id for r in user1.roles_and_parents()]),
                         set([rchild2.id, rparent1.id, rparent2.id]))
        for r in user1.roles_and_parents():
            if r.id == rchild2.id:
                self.assertEqual(r.member, [user1])
            else:
                self.assertIn(r.id, [rparent1.id, rparent2.id])
                self.assertEqual(r.member, [])

