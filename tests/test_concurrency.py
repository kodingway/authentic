from django.db import connection

from authentic2.models import Attribute, AttributeValue

import threading

from utils import skipif_no_partial_index


@skipif_no_partial_index
def test_attribute_value_uniqueness(migrations, transactional_db, simple_user, concurrency):
    from django.db.transaction import set_autocommit
    # disabled default attributes
    Attribute.objects.update(disabled=True)

    set_autocommit(True)
    acount = Attribute.objects.count()

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
    assert Attribute.objects.count() == acount + 2

    def map_threads(f, l):
        threads = []
        for i in l:
            threads.append(threading.Thread(target=f, args=(i,)))
            threads[-1].start()
        for thread in threads:
            thread.join()

    def f(i):
        multiple_at.set_value(simple_user, [str(i)])
    map_threads(f, range(concurrency))
    map_threads(f, range(concurrency))
    assert AttributeValue.objects.filter(attribute=multiple_at).count() == concurrency

    def f(i):
        single_at.set_value(simple_user, str(i))
    map_threads(f, range(concurrency))
    assert AttributeValue.objects.filter(attribute=single_at).count() == 1
