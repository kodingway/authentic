# -*- coding: utf-8 -*-
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

from django.conf import settings
from authentic2.utils import import_from

if getattr(settings, 'ATTRIBUTE_MAPPING', False):
    ATTRIBUTE_MAPPING = import_from(settings.ATTRIBUTE_MAPPING, 'ATTRIBUTE_MAPPING')
    ATTRIBUTE_NAMESPACES = import_from(settings.ATTRIBUTE_MAPPING, 'ATTRIBUTE_NAMESPACES')
else:
    ATTRIBUTE_MAPPING = import_from('authentic2.attribute_aggregator.mapping', 'ATTRIBUTE_MAPPING')
    ATTRIBUTE_NAMESPACES = import_from('authentic2.attribute_aggregator.mapping', 'ATTRIBUTE_NAMESPACES')
