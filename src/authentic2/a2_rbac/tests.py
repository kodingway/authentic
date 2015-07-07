from django.test import TestCase
from django.contrib.contenttypes.models import ContentType
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError

from django_rbac.utils import get_permission_model, get_role_model

Permission = get_permission_model()
Role = get_role_model()
User = get_user_model()


class A2RBACTestCase(TestCase):
    def test_update_rbac(self):
        self.assertEquals(Role.objects.count(), 9)
        self.assertEquals(Permission.objects.count(), 19)

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
            .get(operation__slug='change')
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

    def test_admin_roles_startswith_a2(self):
        coin = Role.objects.create(name='Coin', slug='coin')
        coin.get_admin_role()
        for role in Role.objects.filter(admin_scope_ct__isnull=False):
            self.assertTrue(role.slug.startswith('_a2'), u'role %s slug must '
                            'start with _a2: %s' % (role.name, role.slug))


    def test_admin_roles_update_slug(self):
        user = User.objects.create(username='john.doe')
        name1 = 'Can manage john.doe'
        slug1 = 'can-manage-john-doe'
        admin_role1 = Role.objects.get_admin_role(user, name1, slug1)
        self.assertEqual(admin_role1.name, name1)
        self.assertEqual(admin_role1.slug, slug1)
        name2 = 'Should manage john.doe'
        slug2 = 'should-manage-john-doe'
        admin_role2 = Role.objects.get_admin_role(user, name2, slug2, update_slug=True)
        self.assertEqual(admin_role2.name, name1)
        self.assertEqual(admin_role2.slug, slug2)
        admin_role3 = Role.objects.get_admin_role(user, name2, slug2, update_name=True)
        self.assertEqual(admin_role3.name, name2)
        self.assertEqual(admin_role3.slug, slug2)

    def test_role_clean(self):
        coin = Role(name=u'Coin')
        coin.clean()
        coin.save()
        self.assertEqual(coin.slug, 'coin')
        with self.assertRaises(ValidationError):
            Role(name='Coin2', slug='coin').clean()
        with self.assertRaises(ValidationError):
            Role(name='Coin', slug='coin2').clean()
        with self.assertRaises(ValidationError):
            Role(name='Coin', slug='_coin').clean()
            Role(name='Coin', slug='_coin').clean()
