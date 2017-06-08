import copy

import django
from django.conf import settings
from django.contrib.contenttypes.models import ContentType
from django.db.models.query import Q

try:
    from django.core.exceptions import FieldDoesNotExist
except ImportError:
    # Django < 1.8
    from django.db.models.fields import FieldDoesNotExist

from . import utils

if django.VERSION < (1, 8, 0):
    from django.db.models import ForeignKey

    def get_fk_model(model, fieldname):
        '''returns None if not foreignkey, otherswise the relevant model'''
        try:
            field_object, model, direct, m2m = model._meta.get_field_by_name(fieldname)
        except FieldDoesNotExist:
            return None
        if not m2m and direct and isinstance(field_object, ForeignKey):
            return field_object.rel.to
        return None
else:
    def get_fk_model(model, fieldname):
        try:
            field = model._meta.get_field('ou')
        except FieldDoesNotExist:
            return None
        else:
            if not field.is_relation or not field.many_to_one:
                return None
            return field.related_model


class DjangoRBACBackend(object):
    _DEFAULT_DJANGO_RBAC_PERMISSIONS_HIERARCHY = {
        'admin': ['change', 'delete', 'add', 'view'],
        'change': ['view'],
        'delete': ['view'],
        'add': ['view'],
    }

    def authenticate(self):
        # this method is mandatory
        pass

    def get_permission_cache(self, user_obj):
        '''Returns the permission cache for an user

           The permission cache is a dictionnary, key can be of many types:
           - `'ou.<ou.id>'` ; contains a list of permissions owner by this user as strings
           (<app_label>.<permission>_<model_name>), those permissions are restricted to objects in
           this organizational unit,
           - `'__all__'`: contains a list of global permissions (applicable to any object in any
           organizaton unit) owner by this user,
           - `'<content_type.id>.<object.pk>'`: contains permissions restricted to a specific
           object,
           - `'<app_label>'`: contains a boolean, it indicates that the user own at least on
           permision on a model of this application.
        '''
        if not hasattr(user_obj, '_rbac_perms_cache'):
            perms_cache = {}
            Permission = utils.get_permission_model()
            qs = Permission.objects.for_user(user_obj)
            ct_ct = ContentType.objects.get_for_model(ContentType)
            qs = qs.select_related('operation')
            for permission in qs:
                target_ct = ContentType.objects.get_for_id(permission.target_ct_id)
                if target_ct == ct_ct:
                    target = ContentType.objects.get_for_id(permission.target_id)
                    app_label = target.app_label
                    model = target.model
                    if permission.ou_id:
                        key = 'ou.%s' % permission.ou_id
                    else:
                        key = '__all__'
                else:
                    app_label = target_ct.app_label
                    model = target_ct.model
                    key = '%s.%s' % (permission.target_ct_id, permission.target_id)
                slug = permission.operation.slug
                perms = [str('%s.%s_%s' % (app_label, slug, model))]
                perm_hierarchy = getattr(settings, 'DJANGO_RBAC_PERMISSIONS_HIERARCHY',
                                         self._DEFAULT_DJANGO_RBAC_PERMISSIONS_HIERARCHY)
                if slug in perm_hierarchy:
                    for other_perm in perm_hierarchy[slug]:
                        perms.append(str('%s.%s_%s' % (app_label, other_perm, model)))
                permissions = perms_cache.setdefault(key, set())
                permissions.update(perms)
                # optimization for has_module_perms
                perms_cache[app_label] = True
            user_obj._rbac_perms_cache = perms_cache
        return user_obj._rbac_perms_cache

    def get_all_permissions(self, user_obj, obj=None):
        if user_obj.is_anonymous():
            return ()
        perms_cache = self.get_permission_cache(user_obj)
        if obj:
            permissions = set()
            ct = ContentType.objects.get_for_model(obj)
            key = '%s.%s' % (ct.id, obj.pk)
            if key in perms_cache:
                permissions.update(perms_cache[key])
            for permission in perms_cache.get('__all__', set([])):
                if (permission.startswith('%s.' % ct.app_label)
                        and permission.endswith('_%s' % ct.model)):
                    permissions.add(permission)
            if hasattr(obj, 'ou_id') and obj.ou_id:
                key = 'ou.%s' % obj.ou_id
                for permission in perms_cache.get(key, ()):
                    if (permission.startswith('%s.' % ct.app_label)
                            and permission.endswith('_%s' % ct.model)):
                        permissions.add(permission)
            return permissions
        else:
            return perms_cache.get('__all__', [])

    def has_perm(self, user_obj, perm, obj=None):
        if user_obj.is_anonymous():
            return False
        if not user_obj.is_active:
            return False
        if user_obj.is_superuser:
            return True
        return perm in self.get_all_permissions(user_obj, obj=obj)

    def has_perms(self, user_obj, perm_list, obj=None):
        if user_obj.is_anonymous():
            return False
        if not user_obj.is_active:
            return False
        all_permissions = self.get_all_permissions(user_obj, obj=obj)
        return all(perm in all_permissions for perm in perm_list)

    def has_module_perms(self, user_obj, package_name):
        if user_obj.is_anonymous():
            return False
        if not user_obj.is_active:
            return False
        if user_obj.is_superuser:
            return True
        return package_name in self.get_permission_cache(user_obj)

    def has_perm_any(self, user_obj, perm_or_perms):
        '''Return True if user has any perm on any object'''
        if user_obj.is_anonymous():
            return False
        if not user_obj.is_active:
            return False
        if user_obj.is_superuser:
            return True
        if isinstance(perm_or_perms, basestring):
            perm_or_perms = [perm_or_perms]
        perm_or_perms = set(perm_or_perms)
        cache = self.get_permission_cache(user_obj)
        if perm_or_perms & cache.get('__all__', set()):
            return True
        for key, value in cache.iteritems():
            if isinstance(value, bool):
                continue
            elif key == '__all__':
                continue
            elif key.startswith('ou.'):
                if perm_or_perms & value:
                    return True
            elif perm_or_perms & value:
                return True
        return False

    def filter_by_perm_query(self, user_obj, perm_or_perms, qs):
        '''Create a filter for a queryset for the objects on which the user has
           the given permission. Permissions can be set on individual objects, globally on
           a content type or locally for all objects of an organizational unit.
        '''
        if user_obj.is_anonymous():
            return False
        if not user_obj.is_active:
            return False
        if user_obj.is_superuser:
            return True
        if isinstance(perm_or_perms, basestring):
            perm_or_perms = [perm_or_perms]
        perm_or_perms = set(perm_or_perms)
        cache = self.get_permission_cache(user_obj)
        model = qs.model
        OU = utils.get_ou_model()
        has_ou_field = get_fk_model(model, 'ou') == OU
        if perm_or_perms & cache.get('__all__', set()):
            return True
        q = []
        for key, value in cache.iteritems():
            if isinstance(value, bool):
                continue
            elif key == '__all__':
                continue
            elif key.startswith('ou.'):
                if has_ou_field and perm_or_perms & value:
                    q.append(Q(ou_id=int(key[3:])))
                    continue
            elif perm_or_perms & value:
                ct_id, fk = key.split('.')
                q.append(Q(pk=int(fk)))
        if q:
            return reduce(Q.__or__, q)
        return False

    def filter_by_perm(self, user_obj, perm_or_perms, qs):
        '''Filter a queryset for the objects on which the user has
           the given permission. Permissions can be set on individual objects, globally on
           a content type or locally for all objects of an organizational unit.
        '''
        query = self.filter_by_perm_query(user_obj, perm_or_perms, qs)
        if query is True:
            return copy.deepcopy(qs)
        elif query is False:
            return qs.none()
        else:
            return qs.filter(query)

    def has_ou_perm(self, user_obj, perm, ou):
        if user_obj.is_anonymous():
            return False
        if not user_obj.is_active:
            return False
        if user_obj.is_superuser:
            return True
        if self.has_perm(user_obj, perm):
            return True
        return perm in self.get_permission_cache(user_obj).get('ou.%s' % ou.pk, ())
