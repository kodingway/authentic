from django.contrib.auth.models import Group
from django.db.models.query import Q

from django.contrib.auth import get_user_model


def filter_user(qs, search):
    terms = search.split()
    queries = [ Q(username__icontains=term)
            | Q(first_name__icontains=term)
            | Q(last_name__icontains=term)
            | Q(email__icontains=term) for term in terms]
    return get_user_model().objects.filter(reduce(Q.__and__, queries))

def get_users(search=None):
    User = get_user_model()
    qs = User.objects.order_by('username')
    if search:
        qs = filter_user(qs, search)
    return qs

def search_user(term):
    User = get_user_model()
    return [(u.id, u.get_full_name()) for u in filter_user(User.objects.all(), term)[:10]]
