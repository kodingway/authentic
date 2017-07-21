# authentic2_idp_oidc - Authentic2 OIDC IdP plugin
# Copyright (C) 2017 Entr'ouvert
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import django.apps
from django.utils.encoding import smart_bytes

from rest_framework.exceptions import APIException


class AppConfig(django.apps.AppConfig):
        name = 'authentic2_idp_oidc'

        # implement translation of encrypted pairwise identifiers when and OIDC Client is using the
        # A2 API
        def a2_hook_api_modify_serializer(self, view, serializer):
            from . import utils
            from rest_framework import serializers

            if hasattr(view.request.user, 'oidc_client'):
                client = view.request.user.oidc_client
                if client.identifier_policy == client.POLICY_PAIRWISE_REVERSIBLE:

                    def get_oidc_uuuid(user):
                        return utils.make_pairwise_reversible_sub(client, user)
                    serializer.get_oidc_uuid = get_oidc_uuuid
                    serializer.fields['uuid'] = serializers.SerializerMethodField(
                        method_name='get_oidc_uuid')

        def a2_hook_api_modify_view_before_get_object(self, view):
            '''Decrypt sub used as pk argument in URL.'''
            import uuid
            from . import utils

            request = view.request
            if not hasattr(request.user, 'oidc_client'):
                return
            client = request.user.oidc_client
            if client.identifier_policy != client.POLICY_PAIRWISE_REVERSIBLE:
                return
            lookup_url_kwarg = view.lookup_url_kwarg or view.lookup_field
            if lookup_url_kwarg not in view.kwargs:
                return

            sub = smart_bytes(view.kwargs[lookup_url_kwarg])
            decrypted = utils.reverse_pairwise_sub(client, sub)
            if decrypted:
                view.kwargs[lookup_url_kwarg] = uuid.UUID(bytes=decrypted).hex

        def a2_hook_api_modify_serializer_after_validation(self, view, serializer):
            import uuid
            from . import utils

            if view.__class__.__name__ != 'UsersAPI':
                return
            if serializer.__class__.__name__ != 'SynchronizationSerializer':
                return
            request = view.request
            if not hasattr(request.user, 'oidc_client'):
                return
            client = request.user.oidc_client
            if client.identifier_policy != client.POLICY_PAIRWISE_REVERSIBLE:
                return
            new_known_uuids = []
            uuid_map = request.uuid_map = {}
            request.unknown_uuids = []
            for u in serializer.validated_data['known_uuids']:
                decrypted = utils.reverse_pairwise_sub(client, smart_bytes(u))
                if decrypted:
                    new_known_uuid = uuid.UUID(bytes=decrypted).hex
                    new_known_uuids.append(new_known_uuid)
                    uuid_map[new_known_uuid] = u
                else:
                    request.unknown_uuids.append(u)
                # undecipherable sub are just not checked at all
            serializer.validated_data['known_uuids'] = new_known_uuids

        def a2_hook_api_modify_response(self, view, method_name, data):
            '''Reverse mapping applied in a2_hook_api_modify_serializer_after_validation using the
               uuid_map saved on the request.
            '''
            request = view.request
            if not hasattr(request.user, 'oidc_client'):
                return
            if view.__class__.__name__ != 'UsersAPI':
                return
            if method_name != 'synchronization':
                return
            uuid_map = getattr(request, 'uuid_map', {})
            unknown_uuids = data['unknown_uuids']
            new_unknown_uuids = []
            for u in unknown_uuids:
	        new_unknown_uuids.append(uuid_map[u])
            new_unknown_uuids.extend(request.unknown_uuids)
            data['unknown_uuids'] = new_unknown_uuids
