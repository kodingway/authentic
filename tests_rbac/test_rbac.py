import pytest
import time

from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.test.utils import CaptureQueriesContext
from django.db import connection


from django_rbac import utils, models, backends


def test_role_parenting(db):
    OrganizationalUnit = utils.get_ou_model()
    Role = utils.get_role_model()
    RoleParenting = utils.get_role_parenting_model()

    ou = OrganizationalUnit.objects.create(name='ou')
    roles = []
    for i in range(10):
        roles.append(Role.objects.create(name='r%d' % i, ou=ou))

    assert Role.objects.count() == 10
    assert RoleParenting.objects.count() == 0
    for i in range(1, 3):
        RoleParenting.objects.create(
            parent=roles[i - 1],
            child=roles[i])
    assert RoleParenting.objects.filter(direct=True).count() == 2
    assert RoleParenting.objects.filter(direct=False).count() == 1
    for i, role in enumerate(roles[:3]):
        assert role.children().count() == 3 - i
        assert role.parents().count() == i + 1
        assert role.children(False).count() == 3 - i - 1
        assert role.parents(False).count() == i

    for i in range(4, 6):
        RoleParenting.objects.create(
            parent=roles[i - 1],
            child=roles[i])
    assert RoleParenting.objects.filter(direct=True).count() == 4
    assert RoleParenting.objects.filter(direct=False).count() == 2
    for i, role in enumerate(roles[3:6]):
        assert role.children().count() == 3 - i
        assert role.parents().count() == i + 1
        assert role.children(False).count() == 3 - i - 1
        assert role.parents(False).count() == i
    RoleParenting.objects.create(parent=roles[2], child=roles[3])
    assert RoleParenting.objects.filter(direct=True).count() == 5
    assert RoleParenting.objects.filter(direct=False).count() == 10
    for i in range(6):
        assert roles[i].parents().distinct().count() == i + 1
    for i, role in enumerate(roles[:6]):
        assert role.children().count() == 6 - i
        assert role.parents().count() == i + 1
        assert role.children(False).count() == 6 - i - 1
        assert role.parents(False).count() == i
    RoleParenting.objects.filter(parent=roles[2], child=roles[3],
                                 direct=True).delete()
    assert RoleParenting.objects.filter(direct=True).count() == 4
    assert RoleParenting.objects.filter(direct=False).count() == 2
    # test that it works with cycles
    RoleParenting.objects.create(parent=roles[2], child=roles[3])
    RoleParenting.objects.create(parent=roles[5], child=roles[0])
    for role in roles[:6]:
        assert role.children().count() == 6
        assert role.parents().count() == 6

SIZE = 1000
SPAN = 50


def test_massive_role_parenting(db):

    User = get_user_model()
    Role = utils.get_role_model()
    RoleParenting = utils.get_role_parenting_model()
    Permission = utils.get_permission_model()
    user = User.objects.create(username='user')
    roles = []
    # Try a depth=10 tree of roles
    for i in range(0, SIZE):
        name = 'role%s' % i
        roles.append(
            Role(pk=i + 1, name=name, slug=name))
    Role.objects.bulk_create(roles)
    relations = []
    for i in range(0, SIZE):
        if not i:
            continue
        relations.append(
            RoleParenting(parent=roles[i], child=roles[(i - 1) / SPAN]))
    RoleParenting.objects.bulk_create(relations)
    RoleParenting.objects.update_transitive_closure()
    operation, created = models.Operation.objects.get_or_create(
        slug='admin', defaults={'name': 'Administration'})
    perm, created = Permission.objects.get_or_create(
        operation=operation,
        target_ct=ContentType.objects.get_for_model(ContentType),
        target_id=ContentType.objects.get_for_model(User).id)
    roles[0].members.add(user)
    Role.objects.get(pk=roles[-1].pk).permissions.add(perm)
    b = time.time()
    for i in range(1000):
        assert models.Operation.objects.has_perm(user, 'admin', User)
    t = time.time() - b
    assert float(t) / 1000 < 0.008
    b = time.time()
    for i in range(1000):
        assert (list(Role.objects.for_user(user).order_by('pk')) ==
                list(Role.objects.order_by('pk')))
    t = time.time() - b
    assert float(t) / 1000 < 0.1
    b = time.time()


def test_rbac_backend(db):
    Permission = utils.get_permission_model()
    User = get_user_model()
    OU = utils.get_ou_model()
    ou1 = OU.objects.create(name=u'ou1', slug=u'ou1')
    ou2 = OU.objects.create(name=u'ou2', slug=u'ou2')
    user1 = User.objects.create(username='john.doe')
    Role = utils.get_role_model()
    ct_ct = ContentType.objects.get_for_model(ContentType)
    role_ct = ContentType.objects.get_for_model(Role)
    change_op = models.Operation.objects.get(slug='change')
    view_op = models.Operation.objects.get(slug='view')
    delete_op = models.Operation.objects.get(slug='delete')
    add_op = models.Operation.objects.get(slug='add')
    admin_op = models.Operation.objects.get(slug='admin')
    perm1 = Permission.objects.create(operation=change_op, target_ct=ct_ct,
                                      target_id=role_ct.pk)
    perm2 = Permission.objects.create(operation=view_op, target_ct=ct_ct,
                                      target_id=role_ct.pk)
    role1 = Role.objects.create(name='role1')
    role2 = Role.objects.create(name='role2', ou=ou1)
    role1.permissions.add(perm1)
    role2.permissions.add(perm2)
    role1.add_child(role2)
    role2.members.add(user1)
    perm3 = Permission.objects.create(
        operation=delete_op,
        target_ct=role_ct,
        target_id=role1.pk)
    perm4 = Permission.objects.create(
        operation=add_op,
        ou=ou1,
        target_ct=ct_ct,
        target_id=role_ct.pk)
    role1.permissions.add(perm3)
    role1.permissions.add(perm4)

    rbac_backend = backends.DjangoRBACBackend()
    ctx = CaptureQueriesContext(connection)
    with ctx:
        assert rbac_backend.get_all_permissions(user1) == set(['django_rbac.change_role',
                                                               'django_rbac.search_role',
                                                               'django_rbac.view_role'])
        assert rbac_backend.get_all_permissions(user1, obj=role1) == set(['django_rbac.delete_role',
                                                                          'django_rbac.change_role',
                                                                          'django_rbac.search_role',
                                                                          'django_rbac.view_role'])
        assert rbac_backend.get_all_permissions(user1, obj=role2) == set(['django_rbac.change_role',
                                                                          'django_rbac.view_role',
                                                                          'django_rbac.search_role',
                                                                          'django_rbac.add_role'])
        assert not rbac_backend.has_perm(user1, 'django_rbac.delete_role', obj=role2)
        assert rbac_backend.has_perm(user1, 'django_rbac.delete_role', obj=role1)
        assert rbac_backend.has_perms(user1, ['django_rbac.delete_role', 'django_rbac.change_role',
                                              'django_rbac.view_role'],
                                      obj=role1)
        assert rbac_backend.has_module_perms(user1, 'django_rbac')
        assert not rbac_backend.has_module_perms(user1, 'contenttypes')
    assert len(ctx.captured_queries) == 1
    assert (set(rbac_backend.filter_by_perm(user1, 'django_rbac.add_role', Role.objects.all())) ==
            set([role2]))
    assert (set(rbac_backend.filter_by_perm(user1, 'django_rbac.delete_role', Role.objects.all()))
            == set([role1]))
    assert set(rbac_backend.filter_by_perm(user1, ['django_rbac.delete_role',
                                                   'django_rbac.add_role'],
                                           Role.objects.all())) == set([role1, role2])
    assert (set(rbac_backend.filter_by_perm(user1, 'django_rbac.view_role', Role.objects.all())) ==
            set([role1, role2]))
    assert (set(rbac_backend.filter_by_perm(user1, 'django_rbac.change_role', Role.objects.all()))
            == set([role1, role2]))

    # Test admin op as a generalization of other ops
    user2 = User.objects.create(username='donald.knuth')
    role3 = Role.objects.create(name='role3')
    role3.members.add(user2)
    perm5 = Permission.objects.create(
        operation=admin_op,
        target_ct=ct_ct,
        target_id=role_ct.pk)
    role3.permissions.add(perm5)
    assert rbac_backend.get_all_permissions(user2) == set(['django_rbac.add_role',
                                                           'django_rbac.change_role',
                                                           'django_rbac.search_role',
                                                           'django_rbac.admin_role',
                                                           'django_rbac.view_role',
                                                           'django_rbac.delete_role'])

    # test ous_with_perm
    assert set(rbac_backend.ous_with_perm(user1, 'django_rbac.add_role')) == set([ou1])
    assert set(rbac_backend.ous_with_perm(user1, 'django_rbac.view_role')) == set([ou1, ou2])
    assert set(rbac_backend.ous_with_perm(user1, 'django_rbac.delete_role')) == set([])


def test_all_members(db):
    User = get_user_model()
    u1 = User.objects.create(username='john.doe')
    u2 = User.objects.create(username='donald.knuth')
    u3 = User.objects.create(username='alan.turing')
    Role = utils.get_role_model()
    r1 = Role.objects.create(name='r1')
    r1.members.add(u1)
    r1.members.add(u3)
    r2 = Role.objects.create(name='r2')
    r2.members.add(u3)
    r3 = Role.objects.create(name='r3')
    r3.members.add(u2)
    r3.members.add(u3)
    r3.add_parent(r2)
    r2.add_parent(r1)
    for member in r1.all_members():
        if member == u1 or member == u3:
            assert member.direct == [r1]
        if member == u2:
            assert member.direct == []
    for member in Role.objects.filter(id=r1.id).all_members():
        if member == u1 or member == u3:
            assert member.direct == [r1]
        if member == u2:
            assert member.direct == []
