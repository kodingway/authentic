import json

from django.core.exceptions import PermissionDenied
from django.views.generic.base import ContextMixin
from django.views.generic import TemplateView, FormView, UpdateView, \
    CreateView, DeleteView, TemplateView
from django.views.generic.detail import SingleObjectMixin
from django.http import HttpResponse, Http404
from django.utils.encoding import force_text
from django.utils.translation import ugettext_lazy as _
from django.utils.timezone import now
from django.core.urlresolvers import reverse
from django.contrib.messages.views import SuccessMessageMixin

from django_tables2 import SingleTableView, SingleTableMixin

from django_rbac.utils import get_ou_model

from authentic2.forms import modelform_factory
from authentic2.utils import redirect
from authentic2.decorators import json as json_view

from . import app_settings


class PermissionMixin(object):
    permissions = None

    def authorize(self, request, *args, **kwargs):
        return True

    def dispatch(self, request, *args, **kwargs):
        if hasattr(self, 'model'):
            app_label = self.model._meta.app_label
            model_name = self.model._meta.model_name
            add_perm = '%s.add_%s' % (app_label, model_name)
            self.can_add = request.user.has_perm_any(add_perm)
            if hasattr(self, 'get_object') \
                    and hasattr(self, 'pk_url_kwarg') \
                    and self.pk_url_kwarg in self.kwargs:
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

        if not self.authorize(request, *args, **kwargs):
            raise PermissionDenied

        return super(PermissionMixin, self).dispatch(request, *args, **kwargs)


def filter_view(request, qs):
    model = qs.model
    perm = '%s.view_%s' % (model._meta.app_label, model._meta.model_name)
    return request.user.filter_by_perm(perm, qs)


class FilterQuerysetByPermMixin(object):
    def get_queryset(self):
        qs = super(FilterQuerysetByPermMixin, self).get_queryset()
        return filter_view(self.request, qs)


class FilterTableQuerysetByPermMixin(object):
    def get_table_data(self):
        qs = super(FilterTableQuerysetByPermMixin, self).get_table_data()
        return filter_view(self.request, qs)


class FilterDatasetQuerysetByPermMixin(object):
    def get_dataset(self):
        qs = super(FilterDatasetQuerysetByPermMixin, self).get_dataset()
        return filter_view(self.request, qs)


class TableQuerysetMixin(object):
    def get_table_queryset(self):
        return self.get_queryset()

    def get_table_data(self):
        return self.get_table_queryset()


class PassRequestToFormMixin(object):
    def get_form_kwargs(self):
        kwargs = super(PassRequestToFormMixin, self).get_form_kwargs()
        kwargs['request'] = self.request
        return kwargs


class SearchFormMixin(object):
    search_form_class = None

    def get_search_form_class(self):
        return self.search_form_class

    def get_search_form_kwargs(self):
        return {'data': self.request.GET}

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

    def get_table_data(self):
        qs = super(SearchFormMixin, self).get_table_data()
        if self.search_form and self.search_form.is_valid():
            qs = self.search_form.filter(qs)
        return qs


class FormatsContextData(object):
    formats = ['csv', 'json', 'ods', 'html']

    def get_context_data(self, **kwargs):
        ctx = super(FormatsContextData, self).get_context_data(**kwargs)
        ctx['formats'] = self.formats
        return ctx


class Action(object):
    def __init__(self, name, title, confirm=None, display=True, url_name=None, url=None):
        self.name = name
        self.title = title
        self.confirm = confirm
        self.display = display
        self.url_name = url_name
        self.url = url


class AjaxFormViewMixin(object):
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
    title = None

    def get_title(self):
        return self.title

    def get_context_data(self, **kwargs):
        ctx = super(TitleMixin, self).get_context_data(**kwargs)
        ctx['title'] = self.get_title()
        return ctx


class ActionMixin(object):
    action = None

    def get_context_data(self, **kwargs):
        ctx = super(ActionMixin, self).get_context_data(**kwargs)
        if self.action:
            ctx['action'] = self.action
        return ctx


class OtherActionsMixin(object):
    other_actions = None

    def get_context_data(self, **kwargs):
        ctx = super(OtherActionsMixin, self).get_context_data(**kwargs)
        ctx['other_actions'] = tuple(self.get_displayed_other_actions())
        return ctx

    def get_other_actions(self):
        return self.other_actions or ()

    def get_displayed_other_actions(self):
        return [action for action in self.get_other_actions() if
                action.display]

    def post(self, request, *args, **kwargs):
        self.object = self.get_object()
        for action in self.get_other_actions():
            if action.name in request.POST:
                method = getattr(self, 'action_' + action.name, None)
                if method:
                    response = method(request, *args, **kwargs)
                    if response:
                        return response
                self.request.method = 'GET'
                return self.get(request, *args, **kwargs)
        return super(OtherActionsMixin, self).post(request, *args, **kwargs)


class ExportMixin(object):
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


class ModelNameMixin(object):
    def get_model_name(self):
        return self.model._meta.verbose_name

    def get_context_data(self, **kwargs):
        ctx = super(ModelNameMixin, self).get_context_data(**kwargs)
        ctx['model_name'] = self.get_model_name()
        return ctx


class BaseTableView(FormatsContextData, ModelNameMixin, PermissionMixin,
                    SearchFormMixin, FilterQuerysetByPermMixin,
                    TableQuerysetMixin, SingleTableView):
    pass

class SubTableViewMixin(FormatsContextData, PermissionMixin,
                        SearchFormMixin, FilterTableQuerysetByPermMixin,
                        TableQuerysetMixin, SingleObjectMixin,
                        SingleTableMixin, ContextMixin):
    pass

class SimpleSubTableView(SubTableViewMixin, TemplateView):
    pass

class BaseSubTableView(SubTableViewMixin, FormView):
    success_url = '.'


class BaseDeleteView(TitleMixin, ModelNameMixin, PermissionMixin,
                     AjaxFormViewMixin, DeleteView):
    template_name = 'authentic2/manager/delete.html'

    def authorize(self, *args, **kwargs):
        return self.can_delete

    def get_title(self):
        return _('Delete %s') % self.get_model_name()

    def get_success_url(self):
        return '../../'


class ModelFormView(object):
    fields = None
    form_class = None

    def get_fields(self):
        return self.fields

    def get_form_class(self):
        return modelform_factory(self.model, form=self.form_class,
                                 fields=self.get_fields())


class BaseAddView(TitleMixin, ModelNameMixin, PermissionMixin,
                  AjaxFormViewMixin, ModelFormView, CreateView):
    template_name = 'authentic2/manager/form.html'
    success_view_name = None

    def authorize(self, *args, **kwargs):
        return self.can_add

    def get_title(self):
        return _('Add %s') % self.get_model_name()

    def get_success_url(self):
        return reverse(self.success_view_name, kwargs={'pk': self.object.pk})


class BaseEditView(SuccessMessageMixin, TitleMixin, ModelNameMixin, PermissionMixin,
                   AjaxFormViewMixin, ModelFormView, UpdateView):
    template_name = 'authentic2/manager/form.html'

    def authorize(self, *args, **kwargs):
        return self.can_change

    def get_title(self):
        return self.title or _('Edit %s') % self.get_model_name()

    def get_success_url(self):
        return '..'


class HomepageView(PermissionMixin, TemplateView):
    template_name = 'authentic2/manager/homepage.html'
    permissions = ['a2_rbac.view_role', 'a2_rbac.view_organizationalunit',
                   'auth.view_group', 'custom_user.view_user']

    def dispatch(self, request, *args, **kwargs):
        if app_settings.HOMEPAGE_URL:
            return redirect(request, app_settings.HOMEPAGE_URL)
        return super(HomepageView, self).dispatch(request, *args, **kwargs)


homepage = HomepageView.as_view()


@json_view
def menu_json(request):
    menu_entries = []
    if request.user.has_perm_any('a2_rbac.view_organizationalunit'):
        menu_entries.append({
            'label': force_text(_('Organizational units management')),
            'slug': 'organizational-units',
            'url': request.build_absolute_uri(reverse('a2-manager-ous'))
            })
    if request.user.has_perm_any('custom_user.view_user'):
        menu_entries.append({
            'label': force_text(_('User management')),
            'slug': 'users',
            'url': request.build_absolute_uri(reverse('a2-manager-users'))
            })
    if request.user.has_perm_any('a2_rbac.view_role'):
        menu_entries.append({
            'label': force_text(_('Roles management')),
            'slug': 'roles',
            'url': request.build_absolute_uri(reverse('a2-manager-roles'))
            })
    if request.user.has_perm_any('a2_rbac.view_service'):
        menu_entries.append({
            'label': force_text(_('Services management')),
            'slug': 'services',
            'url': request.build_absolute_uri(reverse('a2-manager-services'))
            })
    return menu_entries


class HideOUColumnMixin(object):
    def get_table(self, **kwargs):
        OU = get_ou_model()
        if OU.objects.count() < 2:
            kwargs['exclude'] = ['ou']
        return super(HideOUColumnMixin, self).get_table(**kwargs)
