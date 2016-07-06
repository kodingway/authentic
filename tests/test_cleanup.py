import datetime

from authentic2.models import DeletedUser
from django.contrib.auth import get_user_model
from django.utils.timezone import now


def test_deleted_user_cleanup(db):
    User = get_user_model()
    u = User.objects.create(username='john.doe')
    assert User.objects.count() == 1
    DeletedUser.objects.delete_user(u)
    DeletedUser.objects.cleanup(timestamp=now() + datetime.timedelta(seconds=700))
    assert User.objects.count() == 0
