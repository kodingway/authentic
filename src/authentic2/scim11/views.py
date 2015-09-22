import re
import json

from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404
from django.http import Http404
from django.core.urlresolvers import reverse
from django.db.models.query import Q

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import authentication, permissions, status
from rest_framework.exceptions import PermissionDenied

SCHEMA_CORE_URN = 'urn:scim:schemas:core:1.0'

TOKENIZER_RE = re.compile(r'(\(|\)|\w+(?:\.\w+)*|"(?:\\"|[^"])*") *')
ATTRIBUTE_RE = re.compile(r'^\w+(?:\.\w+)*$')

def parse(filter_string):
    tokens = re.findall(TOKENIZER_RE, filter_string)
    def parse_attribute_operator(tokens):
        if len(tokens) < 2:
            return
        (attribute, op), new_tokens = tokens[:2], tokens[2:]
        if not re.match(ATTRIBUTE_RE, attribute):
            return
        attribute = attribute.split('.')
        if op not in ('eq', 'co', 'sw', 'pr', 'gt', 'ge', 'lt', 'le'):
            return
        if op != 'pr':
            if len(new_tokens) < 1:
                return
            value, new_tokens = new_tokens[0], new_tokens[1:]
            value = json.loads(value)
            return (op, attribute, value), new_tokens
        else:
            return (op, attribute), new_tokens

    def parse_parenthesis(tokens):
        if len(tokens) < 4:
            return
        if tokens[0] != '(':
            return
        parsed = parse_expr(tokens[1:])
        if not parsed:
            return
        value, new_tokens = parsed
        if len(new_tokens) < 1:
            return
        if new_tokens[0] != ')':
            return
        return value, new_tokens[1:]

    def parse_binary(tokens, op, parser_left, parser_right):
        parsed = parser_left(tokens)
        if not parsed:
            return
        value1, new_tokens = parsed
        if len(new_tokens) < 1:
            return value1, new_tokens
        if new_tokens[0] != op:
            return value1, new_tokens
        parsed = parser_right(new_tokens[1:])
        if not parsed:
            return
        value2, new_tokens = parsed
        return (op, value1, value2), new_tokens

    def parse_and(tokens):
        return parse_binary(tokens, 'and', parse_atom, parse_and)

    def parse_or(tokens):
        return parse_binary(tokens, 'or', parse_and, parse_or)

    def parse_atom(tokens):
        parsed = parse_attribute_operator(tokens)
        if parsed:
            return parsed
        parsed = parse_parenthesis(tokens)
        if parsed:
            return parsed

    def parse_expr(tokens):
        for parser in (parse_or, parse_and, parse_atom, parse_parenthesis):
            parsed = parser(tokens)
            if parsed:
                return parsed

    parsed = parse_expr(tokens)
    if not parsed:
        raise ValueError('invalid scim filter %r' % filter_string)
    value, other_tokens = parsed
    if other_tokens:
        raise ValueError('invalid scim filter, found extra tokens %r' % other_tokens)
    return value


def parse_tree_to_filter(pt):
    op = pt[0]
    if op == 'and':
        return parse_tree_to_filter(pt[1]) & parse_tree_to_filter(pt[2])
    if op == 'or':
        return parse_tree_to_filter(pt[1]) & parse_tree_to_filter(pt[2])
    attribute_map = {
        ('userName',): 'username',
        ('userName', 'givenName'): 'first_name',
        ('userName', 'familyName'): 'last_name',
        ('emails',): 'email',
    }
    if tuple(pt[1]) not in attribute_map:
        raise ValueError('filter attribute %r is unsupported' % pt[1])
    selector = attribute_map[tuple(pt[1])]
    op_map = {
        'eq': '__iexact',
        'co': '__icontains',
        'sw': '__istartswith',
        'pr': '__isnull',
        'gt': '__gt',
        'ge': '__gte',
        'lt': '__lt',
        'le': '__lte',
    }
    selector += op_map[op]
    if op == 'pr':
        value = False
    else:
        value = pt[2]
    return Q(**{selector: value})


class BaseScimView(APIView):
    authentication_classes = (
        authentication.SessionAuthentication,
        authentication.BasicAuthentication,
    )
    permission_classes = (
        permissions.IsAuthenticated,
    )

class UserResource(object):
    @classmethod
    def convert(cls, user):
        location = reverse('a2-scim11', 
                           kwargs={
                               'resource_endpoint': 'Users',
                               'resource_id': user.uuid}
                          )
        data = {
            'id': user.uuid,
            'schemas': [SCHEMA_CORE_URN],
            'userName': user.username,
            'name': {
                'formatted': user.get_full_name(),
                'familyName': user.last_name,
                'givenName': user.first_name,
            },
            'meta': {
                'location': location,
                'created': user.date_joined.isoformat('T'),
            },
        }
        if user.email:
            data['emails'] = [
                {
                    'primary': True,
                    'value': user.email,
                }
            ]
        return data

    @classmethod
    def get_unique(cls, resource_id):
        User = get_user_model()
        user = get_object_or_404(User, uuid=resource_id)
        return cls.convert(user)

    @classmethod
    def listing(cls, search_filter=None):
        User = get_user_model()
        qs = User.objects.all()
        if search_filter:
            query = parse_tree_to_filter(search_filter)
            qs = qs.filter(query)
        count = qs.count()
        def helper(qs):
            for user in qs:
                yield cls.convert(user)
        return count, [SCHEMA_CORE_URN], helper(qs)


class ServiceProviderConfig(object):
    @classmethod
    def mono(cls):
        return {}


RESOURCES = {
    'ServiceProviderConfigs': ServiceProviderConfig,
    'Users': UserResource,
}

class SCIM11(BaseScimView):
    def get(self, request, resource_endpoint, resource_id):
        if resource_endpoint not in RESOURCES:
            raise Http404
        resource = RESOURCES[resource_endpoint]
        mono = hasattr(resource, 'mono')
        if mono:
            if resource_id:
                return Http404
            else:
                return Response(resource.mono())
        if resource_id:
            return Response(resource.get_unique(resource_id))
        else:
            search_filter = None
            if 'filter' in request.GET:
                search_filter = parse(request.GET['filter'])
            count, schemas, generator = resource.listing(search_filter=search_filter)
            data = {
                'totalResults': count,
                'schemas': schemas,
                'Resources': [],
            }
            for d in generator:
                if 'schemas' in d:
                    del d['schemas']
                data['Resources'].append(d)
            return Response(data)

scim11 = SCIM11.as_view()
