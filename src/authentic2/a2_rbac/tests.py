from django.test import TestCase
from django.contrib.contenttypes.models import ContentType
from django.contrib.auth import get_user_model

from django_rbac.utils import get_permission_model, get_role_model

Permission = get_permission_model()
Role = get_role_model()
User = get_user_model()


class A2RBACTestCase(TestCase):
    def test_update_rbac(self):
        self.assertEquals(Role.objects.count(), 8)
        self.assertEquals(Permission.objects.count(), 16)

    def test_delete_role(self):
        rcount = Role.objects.count()
        pcount = Permission.objects.count()
        new_role = Role.objects.create(name='Coucou')
        admin_role = new_role.get_admin_role()

        # There should two more roles, the role and its admin counterpart
        self.assertEquals(Role.objects.count(), rcount+2)

        # There should be two more permissions the admin permission on the role
        # and the admin permission on the admin role
        admin_perm = Permission.objects.by_target(new_role) \
            .get(operation__slug='admin')
        admin_role = Role.objects.get(
            admin_scope_ct=ContentType.objects.get_for_model(admin_perm),
            admin_scope_id=admin_perm.pk)
        admin_admin_perm = Permission.objects.by_target(admin_role) \
            .get(operation__slug='admin')
        self.assertEquals(Permission.objects.count(), pcount+2)
        new_role.delete()
        with self.assertRaises(Permission.DoesNotExist):
            Permission.objects.get(pk=admin_perm.pk)
        with self.assertRaises(Role.DoesNotExist):
            Role.objects.get(pk=admin_role.pk)
        with self.assertRaises(Permission.DoesNotExist):
            Permission.objects.get(pk=admin_admin_perm.pk)
        self.assertEquals(Role.objects.count(), rcount)
        self.assertEquals(Permission.objects.count(), pcount)

    def test_access_control(self):
        role_ct = ContentType.objects.get_for_model(Role)
        role_admin_role = Role.objects.get_admin_role(
            role_ct, 'admin %s' % role_ct, 'admin-role')
        user1 = User.objects.create(username='john.doe')
        self.assertTrue(not user1.has_perm('a2_rbac.change_role'))
        self.assertTrue(not user1.has_perm('a2_rbac.view_role'))
        self.assertTrue(not user1.has_perm('a2_rbac.delete_role'))
        self.assertTrue(not user1.has_perm('a2_rbac.add_role'))
        role_admin_role.members.add(user1)
        del user1._rbac_perms_cache
        self.assertTrue(user1.has_perm('a2_rbac.change_role'))
        self.assertTrue(user1.has_perm('a2_rbac.view_role'))
        self.assertTrue(user1.has_perm('a2_rbac.delete_role'))
        self.assertTrue(user1.has_perm('a2_rbac.add_role'))
