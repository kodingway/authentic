from django.core.exceptions import PermissionDenied
from django.utils.translation import ugettext_lazy as _
from django.views.generic import ListView
from django.contrib import messages
from django.contrib.contenttypes.models import ContentType
from django.db.models.query import Q
from django.db.models import Count
from django.core.urlresolvers import reverse
from django.http import Http404

from django_rbac.utils import get_role_model, get_permission_model, \
    get_role_parenting_model, get_ou_model

from . import tables, views, resources, forms


class RolesMixin(object):
    def get_queryset(self):
        qs = super(RolesMixin, self).get_queryset()
        qs = qs.select_related('ou')
        Permission = get_permission_model()
        permission_ct = ContentType.objects.get_for_model(Permission)
        ct_ct = ContentType.objects.get_for_model(ContentType)
        ou_ct = ContentType.objects.get_for_model(get_ou_model())
        permission_qs = Permission.objects.filter(target_ct_id__in=[ct_ct.id, ou_ct.id]) \
            .values_list('id', flat=True)
        # only non role-admin roles, they are accessed through the
        # RoleManager views
        return qs.filter(Q(admin_scope_ct__isnull=True)
                         | Q(admin_scope_ct=permission_ct,
                             admin_scope_id__in=permission_qs))


class RolesView(RolesMixin, views.BaseTableView):
    template_name = 'authentic2/manager/roles.html'
    model = get_role_model()
    table_class = tables.RoleTable
    search_form_class = forms.RoleSearchForm
    permissions = ['a2_rbac.view_role']

    def get_queryset(self):
        qs = super(RolesView, self).get_queryset()
        qs = qs.annotate(member_count=Count('members'))
        return qs


listing = RolesView.as_view()


class RoleAddView(views.PassRequestToFormMixin, views.BaseAddView):
    template_name = 'authentic2/manager/role_add.html'
    model = get_role_model()
    form_class = forms.RoleEditForm
    title = _('Add role')
    success_view_name = 'a2-manager-role-members'

add = RoleAddView.as_view()


class RolesExportView(views.ExportMixin, RolesView):
    resource_class = resources.RoleResource

    def get_data(self):
        return self.get_queryset()

export = RolesExportView.as_view()


class RoleViewMixin(RolesMixin):
    model = get_role_model()


class RoleEditView(RoleViewMixin, views.BaseEditView):
    template_name = 'authentic2/manager/role_edit.html'
    fields = ['name', 'slug', 'description']
    title = _('Edit role description')
    form_class = forms.RoleEditForm

    def post(self, request, *args, **kwargs):
        if not self.can_change:
            raise PermissionDenied
        return super(RoleEditView, self).get(request, *args, **kwargs)

edit = RoleEditView.as_view()


class RoleMembersView(RoleViewMixin, views.BaseSubTableView):
    template_name = 'authentic2/manager/role_members.html'
    table_class = tables.RoleMembersTable
    form_class = forms.ChooseUserForm
    success_url = '.'
    search_form_class = forms.UserSearchForm

    def get_table_queryset(self):
        return self.object.all_members()

    def form_valid(self, form):
        user = form.cleaned_data['user']
        action = form.cleaned_data['action']
        if self.can_change:
            if action == 'add':
                if self.object.members.filter(pk=user.pk).exists():
                    messages.warning(self.request, _('User already in this '
                                     'role.'))
                else:
                    self.object.members.add(user)
            elif action == 'remove':
                self.object.members.remove(user)
        else:
            messages.warning(self.request, _('You are not authorized'))
        return super(RoleMembersView, self).form_valid(form)

members = RoleMembersView.as_view()


class RoleChildrenView(RoleViewMixin, views.BaseSubTableView):
    template_name = 'authentic2/manager/role_children.html'
    table_class = tables.RoleChildrenTable
    form_class = forms.ChooseRoleForm
    search_form_class = forms.NameSearchForm
    success_url = '.'

    def get_table_queryset(self):
        return self.object.children(include_self=False, annotate=True)

    def form_valid(self, form):
        RoleParenting = get_role_parenting_model()
        role = form.cleaned_data['role']
        action = form.cleaned_data['action']
        if self.can_change:
            if action == 'add':
                if RoleParenting.objects.filter(parent=self.object, child=role,
                                                direct=True).exists():
                    messages.warning(self.request, _('Role "%s" is already a '
                                     'child of this role.') % role.name)
                else:
                    self.object.add_child(role)
            elif action == 'remove':
                self.object.remove_child(role)
        else:
            messages.warning(self.request, _('You are not authorized'))
        return super(RoleChildrenView, self).form_valid(form)

children = RoleChildrenView.as_view()


class RoleDeleteView(RoleViewMixin, views.BaseDeleteView):
    def post(self, request, *args, **kwargs):
        if not self.can_delete:
            raise PermissionDenied
        return super(RoleDeleteView, self).post(request, *args, **kwargs)

    def get_success_url(self):
        return reverse('a2-manager-roles')

delete = RoleDeleteView.as_view()


class RolePermissionsView(RoleViewMixin, views.BaseSubTableView):
    template_name = 'authentic2/manager/role_permissions.html'
    table_class = tables.PermissionTable
    form_class = forms.ChoosePermissionForm
    success_url = '.'

    def get_table_queryset(self):
        return self.object.permissions.all()

    def form_valid(self, form):
        if self.can_change:
            operation = form.cleaned_data['operation']
            ou = form.cleaned_data['ou']
            target = form.cleaned_data['target']
            action = form.cleaned_data['action']
            if action == 'add':
                Permission = get_permission_model()
                perm, created = Permission.objects \
                    .get_or_create(operation=operation, ou=ou,
                                   target_ct=ContentType.objects.get_for_model(
                                       target),
                                   target_id=target.pk)
                self.object.permissions.add(perm)
        else:
            messages.warning(self.request, _('You are not authorized'))
        return super(RolePermissionsView, self).form_valid(form)

permissions = RolePermissionsView.as_view()


class RoleMembersExportView(views.ExportMixin, RoleMembersView):
    resource_class = resources.UserResource

    def get_data(self):
        return self.get_table_data()

members_export = RoleMembersView.as_view()


class RoleManagerViewMixin(RoleViewMixin):
    model = get_role_model()

    def get_object(self):
        self.role_object = super(RoleManagerViewMixin, self).get_object()
        if self.role_object.admin_scope_ct_id:
            raise Http404
        return self.role_object.get_admin_role()

    def get_context_data(self, **kwargs):
        ctx = super(RoleManagerViewMixin, self).get_context_data(**kwargs)
        ctx['role'] = self.role_object
        return ctx


class RoleManagersView(RoleManagerViewMixin, RoleMembersView):
    template_name = 'authentic2/manager/role_managers.html'

    def get_table_queryset(self):
        return self.object.all_members()

    def form_valid(self, form):
        if self.can_change:
            user = form.cleaned_data['user']
            action = form.cleaned_data['action']
            if action == 'add':
                if self.object.members.filter(pk=user.pk).exists():
                    messages.warning(
                        self.request,
                        _('User already in this role.'))
                else:
                    self.object.members.add(user)
            elif action == 'remove':
                self.object.members.remove(user)
        else:
            messages.warning(self.request, _('You are not authorized'))
        return super(RoleManagersView, self).form_valid(form)

managers = RoleManagersView.as_view()


class RoleManagersRolesView(RoleManagerViewMixin, RoleChildrenView):
    template_name = 'authentic2/manager/role_managers_roles.html'

managers_roles = RoleManagersRolesView.as_view()
