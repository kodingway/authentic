# -*- coding: utf-8 -*-

import string

import ldap.dn
import ldap.filter

class DnFormatter(string.Formatter):
    def get_value(self, key, args, kwargs):
        value = super(DnFormatter, self).get_value(key, args, kwargs)
        return value

    def get_field(self, field_name, args, kwargs):
        value, used_arg = super(DnFormatter, self).get_field(field_name, args, kwargs)
        if isinstance(value, (list, tuple)) and len(value) == 1:
            value = value[0]
        return value, used_arg

    def format_field(self, value, format_spec):
        value = super(DnFormatter, self).format_field(value, format_spec)
        return ldap.dn.escape_dn_chars(value)

class FilterFormatter(string.Formatter):
    def get_value(self, key, args, kwargs):
        value = super(FilterFormatter, self).get_value(key, args, kwargs)
        return value

    def get_field(self, field_name, args, kwargs):
        value, used_arg = super(FilterFormatter, self).get_field(field_name, args, kwargs)
        if isinstance(value, (list, tuple)) and len(value) == 1:
            value = value[0]
        return value, used_arg

    def format_field(self, value, format_spec):
        value = super(FilterFormatter, self).format_field(value, format_spec)
        return ldap.filter.escape_filter_chars(value)
