from authentic2.models import Service
from authentic2.a2_rbac.models import Role, OrganizationalUnit as OU


def test_role_natural_key(db):
    ou = OU.objects.create(name='ou1', slug='ou1')
    service = Service.objects.create(name='s1', slug='s1')
    r1 = Role.objects.create(name='r1', slug='r1')
    r2 = Role.objects.create(name='r2', slug='r2', ou=ou)
    r3 = Role.objects.create(name='r3', slug='r3', service=service)
    r4 = Role.objects.create(name='r4', slug='r4', service=service, ou=ou)

    for r in (r1, r2, r3, r4):
        assert Role.objects.get_by_natural_key(*r.natural_key()) == r
