'''
    Authentic 2 - Versatile Identity Server

    Copyright (C) 2011 Entr'ouvert

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''


try:
    import ldap_sources
except ImportError:
    ldap_sources = None
import user_profile

from django.dispatch import Signal

from . import simple_source

any_attributes_call = Signal(providing_args = ["user"])
listed_attributes_call = Signal(providing_args = ["user", "definitions"])
listed_attributes_with_source_call = Signal(providing_args = \
    ["user", "definitions", "source", "auth_source"])
add_attributes = Signal(providing_args = ["instance", "user", "attributes", "context"])

if ldap_sources:
    any_attributes_call.connect(ldap_sources.get_attributes)
    listed_attributes_call.connect(ldap_sources.get_attributes)
    listed_attributes_with_source_call.connect(ldap_sources.get_attributes)

any_attributes_call.connect(user_profile.get_attributes)
listed_attributes_call.connect(user_profile.get_attributes)
listed_attributes_with_source_call.connect(user_profile.get_attributes)

any_attributes_call.connect(simple_source.get_attributes)
listed_attributes_call.connect(simple_source.get_attributes)
listed_attributes_with_source_call.connect(simple_source.get_attributes)

# Connect to saml2_idp signals
from authentic2.idp.signals import add_attributes_to_response
from . import attributes

add_attributes_to_response.connect(attributes.provide_attributes_at_sso)
