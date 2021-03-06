import json
import inspect

from django.core.exceptions import PermissionDenied
from django.views.generic.base import ContextMixin
from django.views.generic.edit import FormMixinBase
from django.views.generic import (FormView, UpdateView, CreateView, DeleteView, TemplateView,
                                  DetailView)
from django.views.generic.detail import SingleObjectMixin
from django.http import HttpResponse, Http404
from django.utils.encoding import force_text
from django.utils.translation import ugettext_lazy as _
from django.utils.timezone import now
from django.core.urlresolvers import reverse, reverse_lazy
from django.contrib.messages.views import SuccessMessageMixin
from django.forms import MediaDefiningClass

from django_tables2 import SingleTableView, SingleTableMixin

from django_select2.views import AutoResponseView

from django_rbac.utils import get_ou_model

from authentic2.forms import modelform_factory
from authentic2.utils import redirect
from authentic2.decorators import json as json_view
from authentic2 import hooks

from . import app_settings, utils


class MediaMixinBase(MediaDefiningClass, FormMixinBase):
    pass


class MultipleOUMixin(object):
    '''Tell templates if there are multiple OU for adaptation in breadcrumbs for example'''
    def get_context_data(self, **kwargs):
        kwargs['multiple_ou'] = utils.get_ou_count() > 1
        return super(MultipleOUMixin, self).get_context_data(**kwargs)


class MediaMixin(object):
    '''Expose needed CSS and JS files as a media object'''

    __metaclass__ = MediaMixinBase

    class Media:
        js = (
            reverse_lazy('a2-manager-javascript-catalog'),
            'xstatic/jquery.js',
            'jquery/js/jquery.form.js',
            'admin/js/urlify.js',
            'authentic2/js/purl.js',
            'authentic2/manager/js/manager.js',
        )
        css = {
            'all': (
                'authentic2/manager/css/style.css',
            )
        }

    def get_context_data(self, **kwargs):
        kwargs['media'] = self.media
        ctx = super(MediaMixin, self).get_context_data(**kwargs)
        if 'form' in ctx:
            ctx['media'] += ctx['form'].media
        return ctx


class PermissionMixin(object):
    '''Control access to views based on permissions'''
    permissions = None

    def authorize(self, request, *args, **kwargs):
        if hasattr(self, 'model'):
            app_label = self.model._meta.app_label
            model_name = self.model._meta.model_name
            add_perm = '%s.add_%s' % (app_label, model_name)
            self.can_add = request.user.has_perm_any(add_perm)
            if hasattr(self, 'get_object') \
                    and ((hasattr(self, 'pk_url_kwarg')
                          and self.pk_url_kwarg in self.kwargs)
                         or (hasattr(self, 'slug_url_kwarg')
                             and self.slug_url_kwarg in self.kwargs)):
                self.object = self.get_object()
                view_perm = '%s.view_%s' % (app_label, model_name)
                change_perm = '%s.change_%s' % (app_label, model_name)
                delete_perm = '%s.delete_%s' % (app_label, model_name)
                self.can_view = request.user.has_perm(view_perm, self.object)
                self.can_change = request.user.has_perm(change_perm,
                                                        self.object)
                self.can_delete = request.user.has_perm(delete_perm,
                                                        self.object)
                if self.permissions \
                        and not request.user.has_perms(
                            self.permissions, self.object):
                    raise PermissionDenied
            elif self.permissions \
                    and not request.user.has_perm_any(self.permissions):
                raise PermissionDenied
        else:
            if self.permissions \
                    and not request.user.has_perm_any(self.permissions):
                raise PermissionDenied

    def dispatch(self, request, *args, **kwargs):
        self.authorize(request, *args, **kwargs)
        return super(PermissionMixin, self).dispatch(request, *args, **kwargs)


def filter_view(request, qs):
    model = qs.model
    perm = '%s.search_%s' % (model._meta.app_label, model._meta.model_name)
    return request.user.filter_by_perm(perm, qs)


class FilterQuerysetByPermMixin(object):
    def get_queryset(self):
        qs = super(FilterQuerysetByPermMixin, self).get_queryset()
        return filter_view(self.request, qs)


class FilterTableQuerysetByPermMixin(object):
    def get_table_data(self):
        qs = super(FilterTableQuerysetByPermMixin, self).get_table_data()
        if getattr(self, 'filter_table_by_perm', True):
            qs = filter_view(self.request, qs)
        return qs


class FilterDatasetQuerysetByPermMixin(object):
    def get_dataset(self):
        qs = super(FilterDatasetQuerysetByPermMixin, self).get_dataset()
        return filter_view(self.request, qs)


class TableQuerysetMixin(object):
    def get_table_queryset(self):
        return self.get_queryset()

    def get_table_data(self):
        return self.get_table_queryset()


class SearchFormMixin(object):
    '''Handle a search form on the current table view.

       The search form class must implement a .filter(qs) method returning a new queryset.'''

    search_form_class = None

    def get_search_form_class(self):
        return self.search_form_class

    def get_search_form_kwargs(self):
        return {'request': self.request, 'data': self.request.GET}

    def get_search_form(self):
        form_class = self.get_search_form_class()
        if not form_class:
            return
        return form_class(**self.get_search_form_kwargs())

    def dispatch(self, request, *args, **kwargs):
        self.search_form = self.get_search_form()
        return super(SearchFormMixin, self).dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super(SearchFormMixin, self).get_context_data(**kwargs)
        if self.search_form:
            ctx['search_form'] = self.search_form
        return ctx

    def filter_by_search(self, qs):
        if self.search_form and self.search_form.is_valid():
            qs = self.search_form.filter(qs)
        return qs

    def get_table_data(self):
        qs = super(SearchFormMixin, self).get_table_data()
        qs = self.filter_by_search(qs)
        return qs


class FormatsContextData(object):
    '''Export list of supported formats in context'''

    formats = ['csv', 'json', 'ods', 'html']

    def get_context_data(self, **kwargs):
        ctx = super(FormatsContextData, self).get_context_data(**kwargs)
        ctx['formats'] = self.formats
        return ctx


class Action(object):
    '''Describe an action for view supporting multiples actions.'''
    name = None
    title = None
    confirm = None
    url_name = None
    url = None
    popup = True
    permission = None

    def __init__(self, name=None, title=None, confirm=None, url_name=None, url=None,
                 popup=None, permission=None):
        if name is not None:
            self.name = name
        if title is not None:
            self.title = title
        if confirm is not None:
            self.confirm = confirm
        if url_name is not None:
            self.url_name = url_name
        if url is not None:
            self.url = url
        if popup is not None:
            self.popup = popup
        if permission is not None:
            self.permission = permission

    def display(self, instance, request):
        if self.permission:
            return request.user.has_perm(self.permission, instance)
        return True


class AjaxFormViewMixin(object):
    '''Implement a JSON response for view which can be included in an AJAX popup'''
    success_url = '.'

    def dispatch(self, request, *args, **kwargs):
        response = super(AjaxFormViewMixin, self).dispatch(request, *args,
                                                           **kwargs)
        return self.return_ajax_response(request, response)

    def return_ajax_response(self, request, response):
        if not request.is_ajax():
            return response
        data = {}
        if 'Location' in response:
            location = response['Location']
            # empty location means that the view can be used from anywhere
            # and so the redirect URL should not be used
            # otherwise compute an absolute URI from the relative URI
            if location and (not location.startswith('http://')
                             or not location.startswith('https://')
                             or not location.startswith('/')):
                location = request.build_absolute_uri(location)
            data['location'] = location
        if hasattr(response, 'render'):
            response.render()
            data['content'] = response.content
        return HttpResponse(json.dumps(data), content_type='application/json')


class TitleMixin(object):
    '''Mixin to provide a title to the view's template'''
    title = ''

    def get_context_data(self, **kwargs):
        ctx = super(TitleMixin, self).get_context_data(**kwargs)
        if hasattr(self, 'get_title'):
            ctx['title'] = self.get_title() or self.title
        else:
            ctx['title'] = self.title
        return ctx


class ActionMixin(object):
    '''Describe the main action implementd by a view'''
    action = None

    def get_context_data(self, **kwargs):
        ctx = super(ActionMixin, self).get_context_data(**kwargs)
        if self.action:
            ctx['action'] = self.action
        return ctx


class OtherActionsMixin(object):
    '''Describe secondary actions possible on a view'''
    other_actions = None

    def get_context_data(self, **kwargs):
        ctx = super(OtherActionsMixin, self).get_context_data(**kwargs)
        ctx['other_actions'] = tuple(self.get_displayed_other_actions())
        return ctx

    def get_other_actions(self):
        return self.other_actions or []

    def get_displayed_other_actions(self):
        actions = []
        other_actions = list(self.get_other_actions())
        hooks.call_hooks('manager_modify_other_actions', self, other_actions)
        for action in other_actions:
            if callable(action.display) and not action.display(self.object, self.request):
                continue

            if action.display:
                actions.append(action)
        return actions

    def post(self, request, *args, **kwargs):
        self.object = self.get_object()
        for action in self.get_displayed_other_actions():
            if action.name in request.POST:
                response = None
                if hasattr(action, 'do'):
                    response = action.do(self, request, self.object)
                else:
                    method = getattr(self, 'action_' + action.name, None)
                    if method:
                        response = method(request, *args, **kwargs)
                if response:
                    return response
                self.request.method = 'GET'
                return self.get(request, *args, **kwargs)
        parent = super(OtherActionsMixin, self)
        if hasattr(parent, 'post'):
            return parent.post(request, *args, **kwargs)
        return self.get(request, *args, **kwargs)


class ExportMixin(object):
    '''Help in implementd export views'''
    http_method_names = ['get', 'head', 'options']
    export_prefix = ''

    def get_export_prefix(self):
        return self.export_prefix

    def get_dataset(self):
        return self.resource_class().export(self.get_data())

    def get(self, request, *args, **kwargs):
        export_format = kwargs['format'].lower()
        content_types = {
            'csv': 'text/csv',
            'html': 'text/html',
            'json': 'application/json',
            'ods': 'application/vnd.oasis.opendocument.spreadsheet',
        }
        if export_format not in content_types:
            raise Http404('unknown format')
        content = getattr(self.get_dataset(), export_format)
        content_type = content_types[export_format]
        if export_format == 'html':
            content = '<!DOCTYPE html><html><head><meta charset="utf-8"/></head><body>%s</body></html>' % content
        response = HttpResponse(content, content_type=content_type)
        filename = '%s%s.%s' % (self.get_export_prefix(), now().isoformat(),
                                export_format)
        response['Content-Disposition'] = 'attachment; filename="%s"' \
            % filename
        return response


class ModelNameMixin(MediaMixin):
    '''Mixin to provide a model name to view's template'''

    def get_model_name(self):
        return self.model._meta.verbose_name

    def get_title(self):
        if hasattr(self, 'get_object'):
            return unicode(self.get_object())
        return u''

    def get_context_data(self, **kwargs):
        ctx = super(ModelNameMixin, self).get_context_data(**kwargs)
        ctx['model_name'] = self.get_model_name()
        return ctx


class TableHookMixin(object):
    '''Helper class for table views, hiding the OU column from tables if an OU filter exists'''

    def get_table(self, **kwargs):
        table = super(TableHookMixin, self).get_table(**kwargs)
        import copy
        table = copy.deepcopy(table)
        hooks.call_hooks('manager_modify_table', self, table)
        return table


class BaseTableView(TableHookMixin, FormatsContextData, ModelNameMixin, PermissionMixin,
                    SearchFormMixin, FilterQuerysetByPermMixin,
                    TableQuerysetMixin, SingleTableView):
    '''Base class for views showing a table of objects'''
    pass


class SubTableViewMixin(TableHookMixin, FormatsContextData, ModelNameMixin, PermissionMixin,
                        SearchFormMixin, FilterTableQuerysetByPermMixin,
                        TableQuerysetMixin, SingleObjectMixin,
                        SingleTableMixin, ContextMixin):
    '''Helper class for views showing a table of objects related to one object'''
    context_object_name = 'object'


class SimpleSubTableView(SubTableViewMixin, TemplateView):
    '''Base class for views showing a simple table of objects related to one object'''

    pass


class BaseSubTableView(MultipleOUMixin, TitleMixin, SubTableViewMixin, FormView):
    '''Base class for views showing a table of objects related to one object'''
    success_url = '.'

    def get_form_kwargs(self):
        kwargs = super(BaseSubTableView, self).get_form_kwargs()
        if getattr(self.get_form_class(), 'need_request', False):
            kwargs['request'] = self.request
        return kwargs


class BaseDeleteView(TitleMixin, ModelNameMixin, PermissionMixin,
                     AjaxFormViewMixin, DeleteView):
    '''Base class for views implementing deletion of an object'''
    template_name = 'authentic2/manager/delete.html'
    context_object_name = 'object'

    @property
    def permissions(self):
        app_label = self.model._meta.app_label
        model_name = self.model._meta.model_name
        return ['%s.delete_%s' % (app_label, model_name)]

    def get_title(self):
        return _('Delete %s') % super(BaseDeleteView, self).get_title()

    def get_success_url(self):
        return '../../'


class ModelFormView(MediaMixin):
    '''Base class for views showing a form for a model'''
    fields = None
    form_class = None

    def get_fields(self):
        return self.fields

    def get_form_kwargs(self):
        kwargs = super(ModelFormView, self).get_form_kwargs()
        if getattr(self.get_form_class(), 'need_request', False):
            kwargs['request'] = self.request
        return kwargs

    def get_form_class(self):
        return modelform_factory(self.model, form=self.form_class,
                                 fields=self.get_fields())

    def get_form(self, form_class=None):
        form = super(ModelFormView, self).get_form(form_class=form_class)
        hooks.call_hooks('manager_modify_form', self, form)
        return form


class BaseDetailView(MultipleOUMixin, TitleMixin, ModelNameMixin, PermissionMixin, ModelFormView,
                     DetailView):
    context_object_name = 'object'
    form_class = None

    @property
    def permissions(self):
        app_label = self.model._meta.app_label
        model_name = self.model._meta.model_name
        return ['%s.view_%s' % (app_label, model_name)]

    def get_form(self):
        form_class = self.get_form_class()
        if getattr(form_class, 'need_request', False):
            form = form_class(request=self.request, instance=self.object)
        else:
            form = form_class(instance=self.object)
        for field in form.fields.values():
            widget = field.widget
            widget.attrs['disabled'] = ''
            if 'readonly' in widget.attrs:
                del widget.attrs['readonly']
        return form

    def get_context_data(self, **kwargs):
        form = self.get_form()
        hooks.call_hooks('manager_modify_form', self, form)
        kwargs['form'] = form
        ctx = super(BaseDetailView, self).get_context_data(**kwargs)
        return ctx


class BaseAddView(MultipleOUMixin, TitleMixin, ModelNameMixin, PermissionMixin,
                  AjaxFormViewMixin, ModelFormView, CreateView):
    '''Base class for views for adding an instance of a model'''
    template_name = 'authentic2/manager/form.html'
    success_view_name = None
    context_object_name = 'object'

    @property
    def permissions(self):
        app_label = self.model._meta.app_label
        model_name = self.model._meta.model_name
        return ['%s.add_%s' % (app_label, model_name)]

    def get_title(self):
        return self.title or _('Add %s') % super(BaseAddView, self).get_model_name()

    def get_success_url(self):
        return reverse(self.success_view_name, kwargs={'pk': self.object.pk})


class BaseEditView(MultipleOUMixin, SuccessMessageMixin, TitleMixin, ModelNameMixin,
                   PermissionMixin, AjaxFormViewMixin, ModelFormView, UpdateView):
    '''Base class for views for editing an instance of a model'''
    template_name = 'authentic2/manager/form.html'
    context_object_name = 'object'

    @property
    def permissions(self):
        app_label = self.model._meta.app_label
        model_name = self.model._meta.model_name
        return ['%s.change_%s' % (app_label, model_name)]

    def get_title(self):
        return _('Edit %s') % super(BaseEditView, self).get_title()

    def get_success_url(self):
        return '..'


class HomepageView(PermissionMixin, MediaMixin, TemplateView):
    template_name = 'authentic2/manager/homepage.html'
    permissions = ['a2_rbac.search_role', 'a2_rbac.search_organizationalunit',
                   'auth.search_group', 'custom_user.search_user']

    def dispatch(self, request, *args, **kwargs):
        if app_settings.HOMEPAGE_URL:
            return redirect(request, app_settings.HOMEPAGE_URL)
        return super(HomepageView, self).dispatch(request, *args, **kwargs)


homepage = HomepageView.as_view()


@json_view
def menu_json(request):
    menu_entries = []
    if request.user.has_perm_any(('a2_rbac.add_organizationalunit',
                                  'a2_rbac.change_organizationalunit')):
        menu_entries.append({
            'label': force_text(_('Organizational units')),
            'slug': 'organizational-units',
            'url': request.build_absolute_uri(reverse('a2-manager-ous'))
        })
    if request.user.has_perm_any('custom_user.view_user'):
        menu_entries.append({
            'label': force_text(_('Users')),
            'slug': 'users',
            'url': request.build_absolute_uri(reverse('a2-manager-users'))
        })
    if request.user.has_perm_any('a2_rbac.view_role'):
        menu_entries.append({
            'label': force_text(_('Roles')),
            'slug': 'roles',
            'url': request.build_absolute_uri(reverse('a2-manager-roles'))
        })
    if request.user.has_perm_any('a2_rbac.view_service'):
        menu_entries.append({
            'label': force_text(_('Services')),
            'slug': 'services',
            'url': request.build_absolute_uri(reverse('a2-manager-services'))
        })
    return menu_entries


class HideOUColumnMixin(object):
    '''Helper class for table views, hiding the OU column from tables if an OU filter exists'''

    def get_table(self, **kwargs):
        OU = get_ou_model()
        exclude_ou = False
        if (hasattr(self, 'search_form') and self.search_form.is_valid() and
                self.search_form.cleaned_data.get('ou') is not None):
            exclude_ou = True
        if OU.objects.count() < 2:
            exclude_ou = True
        if exclude_ou:
            kwargs['exclude'] = ['ou']
        return super(HideOUColumnMixin, self).get_table(**kwargs)


class Select2View(AutoResponseView):
    '''Overrided default django-select2 view to enforce security checks on Select2 AJAX requests.'''

    def get_widget_or_404(self):
        widget = super(Select2View, self).get_widget_or_404()
        widget.view = self
        if hasattr(widget, 'security_check'):
            if not widget.security_check(self.request, *self.args, **self.kwargs):
                raise PermissionDenied
        return widget

select2 = Select2View.as_view()
