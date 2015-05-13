from django.contrib.auth.models import Group
from django.db.models.query import Q

from django.contrib.auth import get_user_model


def filter_user(qs, search):
    return qs.filter(Q(username__icontains=search)
            | Q(first_name__icontains=search)
            | Q(last_name__icontains=search)
            | Q(email__icontains=search))

def get_users(search=None):
    User = get_user_model()
    qs = User.objects.order_by('username')
    if search:
        qs = filter_user(qs, search)
    return qs

def search_user(term):
    User = get_user_model()
    return [(u.id, u.get_full_name()) for u in filter_user(User.objects.all(), term)[:10]]
