from django_select2.forms import ModelSelect2Widget, ModelSelect2MultipleWidget

from django.contrib.auth import get_user_model

from django_rbac.backends import DjangoRBACBackend
from django_rbac.utils import get_role_model, get_ou_model

from authentic2.models import Service

from . import utils


class SplitTermMixin(object):
    def filter_queryset(self, term, queryset=None):
        if queryset is not None:
            qs = queryset.none()
        else:
            qs = self.get_queryset().none()
        for term in term.split():
            qs |= super(SplitTermMixin, self).filter_queryset(term, queryset=queryset)
        return qs


class SecurityCheckMixin(SplitTermMixin):
    operations = ['change', 'add', 'view', 'delete']

    @property
    def perms(self):
        model = self.queryset.model
        app_label = model._meta.app_label
        model_name = model._meta.model_name
        return ['%s.%s_%s' % (app_label, perm, model_name)
                for perm in self.operations]

    def security_check(self, request, *args, **kwargs):
        return request.user.is_authenticated() \
            and request.user.has_perm_any(self.perms)

    def filter_queryset(self, term, queryset=None):
        '''Only search visible objects'''
        if not hasattr(self, 'view'):
            return []
        request = self.view.request
        qs = super(SecurityCheckMixin, self).filter_queryset(term, queryset=queryset)
        rbac_backend = DjangoRBACBackend()
        return rbac_backend.filter_by_perm(request.user, self.perms, qs)


class RoleLabelMixin(object):
    def label_from_instance(self, obj):
        label = unicode(obj)
        if obj.ou and utils.get_ou_count() > 1:
            label = u'{ou} - {obj}'.format(
                ou=obj.ou, obj=obj)
        return label


class ChooseUserWidget(SecurityCheckMixin, ModelSelect2Widget):
    model = get_user_model()
    search_fields = [
        'username__icontains', 'first_name__icontains',
        'last_name__icontains', 'email__icontains'
    ]

    def label_from_instance(self, user):
        return utils.label_from_user(user)


class ChooseUsersWidget(SecurityCheckMixin, ModelSelect2MultipleWidget):
    model = get_user_model()
    search_fields = [
        'username__icontains', 'first_name__icontains',
        'last_name__icontains', 'email__icontains'
    ]

    def label_from_instance(self, user):
        return utils.label_from_user(user)


class ChooseRoleWidget(RoleLabelMixin, SecurityCheckMixin, ModelSelect2Widget):
    queryset = get_role_model().objects.exclude(slug__startswith='_')
    search_fields = [
        'name__icontains',
        'service__name__icontains',
        'ou__name__icontains',
    ]


class ChooseRolesWidget(RoleLabelMixin, SecurityCheckMixin, ModelSelect2MultipleWidget):
    queryset = get_role_model().objects.exclude(slug__startswith='_')
    search_fields = [
        'name__icontains',
        'service__name__icontains',
        'ou__name__icontains',
    ]


class ChooseRolesForChangeWidget(RoleLabelMixin, SecurityCheckMixin, ModelSelect2MultipleWidget):
    operations = ['change']
    queryset = get_role_model().objects.all()
    search_fields = [
        'name__icontains',
        'service__name__icontains',
        'ou__name__icontains',
    ]


class ChooseOUWidget(SecurityCheckMixin, ModelSelect2Widget):
    model = get_ou_model()
    search_fields = [
        'name__icontains',
    ]


class ChooseServiceWidget(SecurityCheckMixin, ModelSelect2Widget):
    model = Service
    search_fields = [
        'name__icontains',
    ]


class ChooseUserRoleWidget(RoleLabelMixin, SecurityCheckMixin, ModelSelect2Widget):
    operations = ['change']
    model = get_role_model()
    search_fields = [
        'name__icontains',
        'service__name__icontains',
        'ou__name__icontains',
    ]
