from django_select2 import AutoModelSelect2Field, \
    AutoModelSelect2MultipleField, NO_ERR_RESP

from django.contrib.auth.models import Group, Permission
from django.contrib.auth import get_user_model
from django.db.models.query import Q

from django_rbac.backends import DjangoRBACBackend
from django_rbac.utils import get_role_model, get_ou_model

from authentic2.models import Service

from . import utils


class SecurityCheckMixin(object):
    operations = ['change', 'add', 'view', 'delete']

    @property
    def perms(self):
        model = self.queryset.model
        app_label = model._meta.app_label
        model_name = model._meta.model_name
        return ['%s.%s_%s' % (app_label, perm, model_name)
                 for perm in self.operations]

    def security_check(self, request, *args, **kwargs):
        model = self.queryset.model
        app_label = model._meta.app_label
        model_name = model._meta.model_name
        return request.user.is_authenticated() \
            and request.user.has_perm_any(self.perms)

    def prepare_qs_params(self, request, search_term, search_fields):
        '''Only search visible objects'''
        ors = []
        ands = {}
        for term in search_term.split():
            qs_params = super(SecurityCheckMixin, self).prepare_qs_params(
                request, term, search_fields)
            ors.extend(qs_params['or'])
            ands.update(qs_params['and'])
        model = self.queryset.model
        app_label = model._meta.app_label
        model_name = model._meta.model_name
        rbac_backend = DjangoRBACBackend()
        query = rbac_backend.filter_by_perm_query(
            request.user, self.perms, self.queryset)
        if query is False:
            ands['id'] = -1
        elif query is True:
            pass
        else:
            ors = [query & reduce(Q.__or__, ors)]
        return {'or': ors, 'and': ands}


class SplitSearchTermMixin(object):
    def prepare_qs_params(self, request, search_term, search_fields):
        ors = []
        ands = {}
        for term in search_term.split():
            qs_params = super(SplitSearchTermMixin, self).prepare_qs_params(
                request, term, search_fields)
            ors.extend(qs_params['or'])
            ands.update(qs_params['and'])
        return {'or': ors, 'and': ands}


class ChooseUserField(SecurityCheckMixin, SplitSearchTermMixin,
                      AutoModelSelect2Field):
    queryset = get_user_model().objects
    search_fields = [
        'username__icontains', 'first_name__icontains',
        'last_name__icontains', 'email__icontains'
    ]

    def get_results(self, request, term, page, context):
        return (NO_ERR_RESP, False, utils.search_user(term))


class ChooseUsersField(SecurityCheckMixin, SplitSearchTermMixin,
                      AutoModelSelect2MultipleField):
    queryset = get_user_model().objects
    search_fields = [
        'username__icontains', 'first_name__icontains',
        'last_name__icontains', 'email__icontains'
    ]

    def get_results(self, request, term, page, context):
        return (NO_ERR_RESP, False, utils.search_user(term))


class GroupsField(SecurityCheckMixin, SplitSearchTermMixin,
                  AutoModelSelect2MultipleField):
    queryset = Group.objects
    search_fields = [
        'name__icontains',
    ]


class PermissionChoices(SecurityCheckMixin, SplitSearchTermMixin,
                        AutoModelSelect2MultipleField):
    queryset = Permission.objects
    search_fields = [
        'name__icontains', 'codename__icontains',
        'content_type__name__icontains'
    ]

    def prepare_qs_params(self, request, search_term, search_fields):
        ors = []
        ands = {}
        for term in search_term.split():
            qs_params = super(PermissionChoices, self).prepare_qs_params(
                request, term, search_fields)
            ors.extend(qs_params['or'])
            ands.update(qs_params['and'])
        return {'or': ors, 'and': ands}

    def label_from_instance(self, instance):
        return instance.name


class RoleLabelMixin(object):
    def label_from_instance(self, obj):
        label = unicode(obj)
        if obj.service:
            label = label + ' - ' + unicode(obj.service)
        return label


class ChooseRoleField(RoleLabelMixin, SecurityCheckMixin, SplitSearchTermMixin,
                      AutoModelSelect2Field):
    queryset = get_role_model().objects.filter(admin_scope_ct__isnull=True)
    search_fields = [
        'name__icontains',
        'service__name__icontains',
    ]


class ChooseOUField(SecurityCheckMixin, SplitSearchTermMixin,
                    AutoModelSelect2Field):
    queryset = get_ou_model().objects
    search_fields = [
        'name__icontains',
    ]


class ChooseServiceField(SecurityCheckMixin, SplitSearchTermMixin,
                         AutoModelSelect2Field):
    queryset = Service.objects
    search_fields = [
        'name__icontains',
    ]


class ChooseUserRoleField(RoleLabelMixin, SecurityCheckMixin, SplitSearchTermMixin,
                      AutoModelSelect2Field):
    operations = ['change']
    queryset = get_role_model().objects
    search_fields = [
        'name__icontains',
        'service__name__icontains',
    ]
