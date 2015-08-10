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

def label_from_user(user):
    labels = []
    if user.first_name or user.last_name:
        labels.append(user.first_name)
        if user.first_name and user.last_name:
            labels.append(u' ')
        labels.append(user.last_name)
    if user.email and user.email not in labels:
        if labels:
            labels.append(u' - ')
        labels.append(user.email)
    if user.username and user.username not in labels:
        if labels:
            labels.append(u' - ')
        labels.append(user.username)
    return u''.join(labels)

def search_user(term):
    User = get_user_model()
    return [(u.id, label_from_user(u)) for u in filter_user(User.objects.all(), term)[:10]]
