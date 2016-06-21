# -*- coding: utf-8 -*-
from django import forms
from django.forms.widgets import SubWidget
from django.utils.safestring import mark_safe
from django.utils.html import conditional_escape, format_html, escape
from django.forms.utils import flatatt, to_current_timezone


class ListWidget(forms.Widget):
    '''Given a widget, create a multiple value input widget'''
    class Media:
        css = {'all': ['listwidget.css']}
        js = ['xstatic/jquery.js', 'xstatic/jquery-ui.js', 'listwidget.js']

    def __init__(self, widget, initial_length=1, maximum_length=None, attrs=None):
        self.widget = widget() if isinstance(widget, type) else widget
        self.initial_length = initial_length
        self.maximum_length = maximum_length
        super(ListWidget, self).__init__(attrs=attrs)

    def render(self, name, values, attrs=None):
        if self.is_localized:
            self.widget.is_localized = self.is_localized

        final_attrs = self.build_attrs(attrs)
        id_ = final_attrs.get('id', None)
        # template widget
        template_attrs = {}
        if id_:
            template_attrs['id'] = '%s_%s' % (id_, id(self))
            template_attrs['name'] = '%s_%s' % (name, id(self))
        template_widget = '<input type="hidden" id="%s_order" name="%s_order" value="%s"/>' % (
            id_, name, id(self))
        template_widget += self.widget.render('', None, template_attrs)

        l = len(values) if values else self.initial_length

        output = []
        for i, widget in enumerate(self.subwidgets(name, values, attrs=attrs)):
            order_field = '<input type="hidden" id="%s_order" name="%s_order" value="%s"/>' % (
                id_, name, i)
            output.append(order_field + str(widget))

        hidden_count = ('<input type="hidden" id="%s_count" name="%s_count" value="%s"/>'
                        % (id_, name, l))
        button = ('<button type="button" class="list-widget-add-button" '
                  'data-template-id="%s_%s" '
                  'data-needle="%s" '
                  'data-maximum-length="%d">+</button>' %
                  (id_, id(self), id(self), self.maximum_length or 0))

        return mark_safe(self.format_output(template_widget, output) + hidden_count + button)

    def subwidgets(self, name, values, attrs=None, choices=()):
        final_attrs = self.build_attrs(attrs)
        id_ = final_attrs.get('id', None)
        l = len(values) if values else self.initial_length
        for i in xrange(l):
            try:
                widget_value = (values or [])[i]
            except IndexError:
                widget_value = None
            if id_:
                final_attrs = dict(final_attrs, id='%s_%s' % (id_, i))
            yield SubWidget(self.widget, name + '_%s' % i, widget_value, final_attrs,
                            choices=choices)

    def format_output(self, template_widget, rendered_widgets):
        """
        Given a list of rendered widgets (as strings), returns a Unicode string
        representing the HTML for the whole lot.

        This hook allows you to format the HTML design of the widgets, if
        needed.
        """
        output = []
        template_widget = u'<li><span class="handle">⣿</span>%s</li>' % template_widget
        for i, rendered_widget in enumerate(rendered_widgets):
            output.append(u'<li><span class="handle">⣿</span>%s</li>' % rendered_widget)
        return u'<ol class="list-widget" data-template="%s">%s</ol>' % (escape(template_widget),
                                                                        ''.join(output))

    def _get_media(self):
        m = forms.Media()
        m += forms.Media(ListWidget.Media)
        try:
            m += self.widget.media
        except AttributeError:
            pass
        return m
    media = property(_get_media)

    def id_for_label(self, id_):
        # See the comment for RadioSelect.id_for_label()
        if id_:
            id_ += '_0'
        return id_

    def value_from_datadict(self, data, files, name):
        """
        Given a dictionary of data and this widget's name, returns the value
        of this widget. Returns None if it's not provided.
        """
        values = []
        try:
            count = int(data['%s_count' % name])
        except (KeyError, TypeError):
            return []

        try:
            order = data.getlist('%s_order' % name)
        except KeyError:
            return []

        for i in xrange(count):
            sub_name = '%s_%s' % (name, i)
            values.append(self.widget.value_from_datadict(data, files, sub_name))
        ordered = []
        for i in order:
            try:
                i = int(i)
            except ValueError:
                continue
            try:
                ordered.append(values[i])
            except IndexError:
                continue
        ordered = [v for v in ordered if v]
        return ordered

    @property
    def needs_multipart_form(self):
        return self.widget.needs_multipart_form
