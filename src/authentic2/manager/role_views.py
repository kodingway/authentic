from django.core.exceptions import PermissionDenied
from django.utils.translation import ugettext_lazy as _
from django.views.generic import ListView, FormView, TemplateView
from django.views.generic.edit import FormMixin, DeleteView
from django.views.generic.detail import SingleObjectMixin
from django.contrib import messages
from django.contrib.contenttypes.models import ContentType
from django.db.models.query import Q
from django.db.models import Count
from django.core.urlresolvers import reverse
from django.http import Http404

from django_rbac.utils import get_role_model, get_permission_model, \
    get_role_parenting_model, get_ou_model

from authentic2.decorators import setting_enabled
from authentic2.utils import redirect

from . import tables, views, resources, forms, app_settings


class RolesMixin(object):
    service_roles = True
    admin_roles = False

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
        if not self.admin_roles:
            qs = qs.filter(Q(admin_scope_ct__isnull=True) |
                           Q(admin_scope_ct=permission_ct,
                             admin_scope_id__in=permission_qs))
        if not self.service_roles:
            qs = qs.filter(service__isnull=True)
        return qs


class RolesView(views.HideOUColumnMixin, RolesMixin, views.BaseTableView):
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
    title = _('Add role')
    success_view_name = 'a2-manager-role-members'

    def get_form_class(self):
        return forms.get_role_form_class()

add = RoleAddView.as_view()


class RolesExportView(views.ExportMixin, RolesView):
    resource_class = resources.RoleResource

    def get_data(self):
        return self.get_queryset()

export = RolesExportView.as_view()


class RoleViewMixin(RolesMixin):
    model = get_role_model()

    def get_context_data(self, **kwargs):
        kwargs['ROLES_SHOW_PERMISSIONS'] = app_settings.ROLES_SHOW_PERMISSIONS
        return super(RoleViewMixin, self).get_context_data(**kwargs)

class RoleEditView(RoleViewMixin, views.BaseEditView):
    template_name = 'authentic2/manager/role_edit.html'
    title = _('Edit role description')

    def get_form_class(self):
        return forms.get_role_form_class()

edit = RoleEditView.as_view()


class RoleMembersView(views.HideOUColumnMixin, RoleViewMixin, views.BaseSubTableView):
    template_name = 'authentic2/manager/role_members.html'
    table_class = tables.RoleMembersTable
    form_class = forms.ChooseUserForm
    success_url = '.'
    search_form_class = forms.UserSearchForm
    permissions = ['a2_rbac.view_role']

    def get_title(self):
        return self.object

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

    def get_context_data(self, **kwargs):
        ctx = super(RoleMembersView, self).get_context_data(**kwargs)
        ctx['children'] = views.filter_view(self.request,
                                            self.object.children(include_self=False,
                                            annotate=True))
        ctx['parents'] = views.filter_view(self.request,
                                           self.object.parents(include_self=False,
                                           annotate=True))
        return ctx

members = RoleMembersView.as_view()


class RoleChildrenView(views.HideOUColumnMixin, RoleViewMixin, views.BaseSubTableView):
    template_name = 'authentic2/manager/role_children.html'
    table_class = tables.RoleChildrenTable
    form_class = forms.ChooseRoleForm
    search_form_class = forms.RoleSearchForm
    success_url = '.'
    permissions = ['a2_rbac.view_role']

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
    permissions = ['a2_rbac.view_role']

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

permissions = setting_enabled('ROLES_SHOW_PERMISSIONS', app_settings)(
    RolePermissionsView.as_view())


class RoleMembersExportView(views.ExportMixin, RoleMembersView):
    resource_class = resources.UserResource
    permissions = ['a2_rbac.view_role']

    def get_data(self):
        return self.get_table_data()

members_export = RoleMembersExportView.as_view()


class RoleManagerViewMixin(RoleViewMixin):
    model = get_role_model()

    def get_object(self):
        self.role_object = super(RoleManagerViewMixin, self).get_object()
        if self.role_object.has_self_administration():
            raise Http404
        return self.role_object.get_admin_role()

    def get_context_data(self, **kwargs):
        ctx = super(RoleManagerViewMixin, self).get_context_data(**kwargs)
        ctx['role'] = self.role_object
        return ctx


class RoleManagersView(RoleManagerViewMixin, RoleMembersView):
    template_name = 'authentic2/manager/role_managers.html'

managers = RoleManagersView.as_view()


class RoleManagersRolesView(RoleManagerViewMixin, RoleChildrenView):
    template_name = 'authentic2/manager/role_managers_roles.html'

managers_roles = RoleManagersRolesView.as_view()


class RoleAddChildView(views.AjaxFormViewMixin, views.TitleMixin,
                       views.PermissionMixin, SingleObjectMixin, FormView):
    title = _('Add child role')
    model = get_role_model()
    form_class = forms.RolesForm
    success_url = '..'
    template_name = 'authentic2/manager/form.html'
    permissions = 'a2_rbac.change_role'

    def dispatch(self, request, *args, **kwargs):
        self.object = self.get_object()
        return super(RoleAddChildView, self).dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        for role in form.cleaned_data['roles']:
            self.get_object().add_child(role)
        return super(RoleAddChildView, self).form_valid(form)

add_child = RoleAddChildView.as_view()


class RoleAddParentView(views.AjaxFormViewMixin, views.TitleMixin,
                        SingleObjectMixin, FormView):
    title = _('Add parent role')
    model = get_role_model()
    form_class = forms.RoleForm
    success_url = '..'
    template_name = 'authentic2/manager/form.html'

    def dispatch(self, request, *args, **kwargs):
        self.object = self.get_object()
        return super(RoleAddParentView, self).dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        if not self.request.user.has_perm('a2_rbac.change_role',
                                          form.cleaned_data['role']):
            raise PermissionDenied
        self.get_object().add_parent(form.cleaned_data['role'])
        return super(RoleAddParentView, self).form_valid(form)

add_parent = RoleAddParentView.as_view()


class RoleRemoveChildView(views.AjaxFormViewMixin, SingleObjectMixin,
                          views.PermissionMixin, TemplateView):
    title = _('Remove child role')
    model = get_role_model()
    success_url = '../..'
    template_name = 'authentic2/manager/role_remove_child.html'
    permissions = 'a2_rbac.change_role'

    def dispatch(self, request, *args, **kwargs):
        self.object = self.get_object()
        self.child = self.get_queryset().get(pk=kwargs['child_pk'])
        return super(RoleRemoveChildView, self).dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super(RoleRemoveChildView, self).get_context_data(**kwargs)
        ctx['child'] = self.child
        return ctx

    def post(self, request, *args, **kwargs):
        self.object.remove_child(self.child)
        return redirect(self.request, self.success_url)

remove_child = RoleRemoveChildView.as_view()


class RoleRemoveParentView(views.AjaxFormViewMixin, SingleObjectMixin,
                           TemplateView):
    title = _('Remove parent role')
    model = get_role_model()
    success_url = '../..'
    template_name = 'authentic2/manager/role_remove_parent.html'

    def dispatch(self, request, *args, **kwargs):
        self.object = self.get_object()
        self.parent = self.get_queryset().get(pk=kwargs['parent_pk'])
        return super(RoleRemoveParentView, self).dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super(RoleRemoveParentView, self).get_context_data(**kwargs)
        ctx['parent'] = self.parent
        return ctx

    def post(self, request, *args, **kwargs):
        if not self.request.user.has_perm('a2_rbac.change_role', self.parent):
            raise PermissionDenied
        self.object.remove_parent(self.parent)
        return redirect(self.request, self.success_url)

remove_parent = RoleRemoveParentView.as_view()
