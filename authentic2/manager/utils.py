from django.contrib.auth.models import Group, User
from django.db.models.query import Q


class Role(object):
    def __init__(self, name, ref):
        self.name = name
        self.ref = ref

class RoleUser(Role):
    pass


def get_roles():
    return [Role(g.name, g.id) for g in Group.objects.order_by('name')]

def get_role(ref):
    g = Group.objects.get(id=ref)
    return Role(g.name, g.id)

def filter_user(qs, search):
    return qs.filter(Q(username__contains=search)
            | Q(first_name__contains=search)
            | Q(last_name__contains=search)
            | Q(email__contains=search))

def get_role_users(role, search=None):
    qs = User.objects.filter(groups__id=role.ref)
    if search:
        qs = filter_user(qs, search)
    return qs

def role_add(name):
    g, created = Group.objects.get_or_create(name=name)
    return g.id

def search_user(term):
    return [RoleUser(u.get_full_name(), u.id) for u in filter_user(User.objects.all(), term)[:10]]

def add_user_to_role(role, user):
    User.objects.get(id=user).groups.add(Group.objects.get(id=role.ref))

def remove_user_from_role(role, user):
    User.objects.get(id=user).groups.remove(Group.objects.get(id=role.ref))
