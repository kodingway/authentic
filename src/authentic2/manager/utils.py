from django.db.models.query import Q

from django.contrib.auth import get_user_model

from authentic2.models import Attribute


def filter_user(qs, search):
    terms = search.split()

    searchable_attributes = Attribute.objects.filter(searchable=True)
    queries = []
    for term in terms:
        q = (Q(username__icontains=term) | Q(first_name__icontains=term) |
             Q(last_name__icontains=term) | Q(email__icontains=term))
        for a in searchable_attributes:
            if a.name in ('first_name', 'last_name'):
                continue
            q = q | Q(attribute_values__content=term, attribute_values__attribute=a)
        queries.append(q)
    qs = qs.filter(reduce(Q.__and__, queries))
    # search by attributes can match multiple times
    if searchable_attributes:
        qs = qs.distinct()
    return qs


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
