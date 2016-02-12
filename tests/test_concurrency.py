import pytest

from django.db import close_old_connections
from authentic2.models import Attribute, AttributeValue
from authentic2.custom_user.models import User

import threading

def test_attribute_value_uniqueness(transactional_db, simple_user):
    from django.db.transaction import set_autocommit

    set_autocommit(True)
    single_at = Attribute.objects.create(
        name='single',
        label='single',
        kind='string',
        multiple=False)
    multiple_at = Attribute.objects.create(
        name='multiple',
        label='multiple',
        kind='string',
        multiple=True)
    assert Attribute.objects.count() == 2

    def map_threads(f, l):
        threads = []
        for i in l:
            threads.append(threading.Thread(target=f, args=(i,)))
            threads[-1].start()
        for thread in threads:
            thread.join()
    def f(i):
        from django.db import connection
        connection.close()
        multiple_at.set_value(simple_user, [str(i)])
        connection.close()
    map_threads(f, range(100))
    map_threads(f, range(100))
    assert AttributeValue.objects.filter(attribute=multiple_at).count() == 100

    def f(i):
        from django.db import connection
        connection.close()
        single_at.set_value(simple_user, str(i))
        connection.close()
    map_threads(f, range(100))
    assert AttributeValue.objects.filter(attribute=single_at).count() == 1

