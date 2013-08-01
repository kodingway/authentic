from django.db import models
from django.utils.translation import ugettext_lazy as _
from django.db.models.manager import EmptyManager
from django.contrib.auth.models import _user_get_all_permissions, _user_has_perm, _user_has_module_perms


class FakePk:
    name = 'pk'

class FakeMeta:
    pk = FakePk()

class SAML2TransientUser(object):
    '''Class compatible with django.contrib.auth.models.User
       which represent an user authenticated using a Transient
       federation'''
    id = None
    pk = None
    is_staff = False
    is_active = False
    is_superuser = False
    _groups = EmptyManager()
    _user_permissions = EmptyManager()
    _meta = FakeMeta()

    def __init__(self, id):
        self.id = id
        self.pk = id

    def __unicode__(self):
        return 'AnonymousUser'

    def __str__(self):
        return unicode(self).encode('utf-8')

    def __eq__(self, other):
        return isinstance(other, self.__class__)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return 1 # instances always return the same hash value

    def save(self, **kwargs):
        pass

    def delete(self):
        raise NotImplementedError

    def set_password(self, raw_password):
        raise NotImplementedError

    def check_password(self, raw_password):
        raise NotImplementedError

    def _get_groups(self):
        return self._groups
    groups = property(_get_groups)

    def _get_user_permissions(self):
        return self._user_permissions
    user_permissions = property(_get_user_permissions)

    def get_group_permissions(self, obj=None):
        return set()

    def get_all_permissions(self, obj=None):
        return _user_get_all_permissions(self, obj=obj)

    def has_perm(self, perm, obj=None):
        return _user_has_perm(self, perm, obj=obj)

    def has_perms(self, perm_list, obj=None):
        for perm in perm_list:
            if not self.has_perm(perm, obj):
                return False
        return True

    def has_module_perms(self, module):
        return _user_has_module_perms(self, module)

    def is_anonymous(self):
        #XXX: Should return True
        return False

    def is_authenticated(self):
        return True

    def get_username(self):
        return _('Anonymous')
    username = property(get_username)
