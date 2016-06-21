import pytest

from authentic2.models import Service
from authentic2.a2_rbac.models import Role, OrganizationalUnit as OU


def test_role_natural_key(db):
    ou = OU.objects.create(name='ou1', slug='ou1')
    s1 = Service.objects.create(name='s1', slug='s1')
    s2 = Service.objects.create(name='s2', slug='s2', ou=ou)
    r1 = Role.objects.create(name='r1', slug='r1')
    r2 = Role.objects.create(name='r2', slug='r2', ou=ou)
    r3 = Role.objects.create(name='r3', slug='r3', service=s1)
    r4 = Role.objects.create(name='r4', slug='r4', service=s2)

    for r in (r1, r2, r3, r4):
        assert Role.objects.get_by_natural_key(*r.natural_key()) == r
    assert r1.natural_key() == ['r1', None, None]
    assert r2.natural_key() == ['r2', ['ou1'], None]
    assert r3.natural_key() == ['r3', None, [None, 's1']]
    assert r4.natural_key() == ['r4', ['ou1'], [['ou1'], 's2']]
    ou.delete()
    with pytest.raises(Role.DoesNotExist):
        Role.objects.get_by_natural_key(*r2.natural_key())
    with pytest.raises(Role.DoesNotExist):
        Role.objects.get_by_natural_key(*r4.natural_key())
