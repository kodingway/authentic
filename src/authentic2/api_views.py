'''Views for Authentic2 API'''
import smtplib

from django.db import models
from django.contrib.auth import get_user_model
from django.core.exceptions import MultipleObjectsReturned
from django.utils.translation import ugettext as _

from django_rbac.utils import get_ou_model

from rest_framework import serializers
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from rest_framework import authentication, permissions, status
from rest_framework.exceptions import PermissionDenied

from . import utils


class HasUserAddPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        if not request.user.has_perm_any('custom_user.add_user'):
            return False
        return True


class RegistrationSerializer(serializers.Serializer):
    '''Register RPC payload'''
    email = serializers.EmailField()
    ou = serializers.SlugRelatedField(
        queryset=get_ou_model().objects.all(),
        slug_field='slug',
        required=False, allow_null=True)
    username = serializers.CharField(
        required=False, allow_blank=True)
    first_name = serializers.CharField(
        required=False, allow_blank=True)
    last_name = serializers.CharField(
        required=False, allow_blank=True)
    password = serializers.CharField(
        required=False, allow_null=True)
    no_email_validation = serializers.BooleanField(
        required=False)
    return_url = serializers.URLField()

    def validate(self, data):
        request = self.context.get('request')
        if request:
            perm = 'custom_user.add_user'
            if data['ou']:
                authorized = request.user.has_ou_perm(perm, data['ou'])
            else:
                authorized = request.user.has_perm(perm)
            if not authorized:
                raise serializers.ValidationError(_('you are not authorized '
                                                    'to create users in '
                                                    'this ou'))
        User = get_user_model()
        if data['ou'] and data['ou'].email_is_unique and \
                User.objects.filter(ou=data['ou'],
                                   email__iexact=data['email']).exists():
            raise serializers.ValidationError(
                _('You already have an account'))
        if data['ou'] and data['ou'].username_is_unique and not \
                'username' in data:
            raise serializers.ValidationError(
                _('Username is required in this ou'))
        if data['ou'] and data['ou'].username_is_unique and \
               User.objects.filter(ou=data['ou'],
                                   username=data['username']).exists():
            raise serializers.ValidationError(
                _('You already have an account'))
        return data

class RpcMixin(object):
    def post(self, request, format=None):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            response, response_status = self.rpc(request, serializer)
            return Response(response, response_status)
        else:
            response = {'result': 0, 'errors': serializer.errors}
            return Response(response, status.HTTP_400_BAD_REQUEST)


class BaseRpcView(RpcMixin, GenericAPIView):
    authentication_classes = (authentication.BasicAuthentication,)
    permission_classes = (permissions.IsAuthenticated,
                          HasUserAddPermission)


class Register(BaseRpcView):
    '''Register the given email, send a mail to the user and return a
       validation token.

       A mail will be sent to the user to validate its email. On
       validation of the mail the user will be logged and redirected to
       `{return_url}?token={token}`. It's the durty of the requesting
       service to finish the registration process on its side.

       If email is unique and an account already exist the requesting
       must enter in a process of registration through SSO, i.e. ask for
       authentication of the user and then finish the registration
       process for the received identity.
    '''
    serializer_class = RegistrationSerializer

    def rpc(self, request, serializer):
        validated_data = serializer.validated_data
        data = serializer.data
        email = validated_data['email']
        token = utils.get_hex_uuid()[:16]
        final_return_url = utils.make_url(validated_data['return_url'],
                                          params={'token': token})

        registration_template = ['authentic2/activation_email']
        if validated_data['ou']:
            registration_template.insert(0, 'authentic2/activation_email_%s' %
                                         validated_data['ou'].slug)
        registration_data = {}
        for field in ('first_name', 'last_name', 'password', 'username', 'ou'):
            if field in validated_data:
                if isinstance(validated_data[field], models.Model):
                    registration_data[field] = validated_data[field].pk
                else:
                    registration_data[field] = validated_data[field]

        ctx = {
            'registration_data': registration_data,
        }
        try:
            utils.send_registration_mail(self.request, email,
                                         registration_template,
                                         next_url=final_return_url,
                                         ctx=ctx,
                                         **registration_data)
        except smtplib.SMTPException, e:
            response = {
                'result': 0,
                'errors': {
                    '__all__': ['Mail sending failed']
                },
                'exception': unicode(e),
            }
            response_status = status.HTTP_503_SERVICE_UNAVAILABLE
        else:
            response = {
                'result': 1,
                'token': token,
                'request': data,
            }
            response_status = status.HTTP_202_ACCEPTED
        return response, response_status

register = Register.as_view()

class PasswordChangeSerializer(serializers.Serializer):
    '''Register RPC payload'''
    email = serializers.EmailField()
    ou = serializers.SlugRelatedField(
        queryset=get_ou_model().objects.all(),
        slug_field='slug',
        required=False, allow_null=True)
    old_password = serializers.CharField(
        required=True, allow_null=True)
    new_password = serializers.CharField(
        required=True, allow_null=True)

    def validate(self, data):
        User = get_user_model()
        qs = User.objects.filter(email=data['email'])
        if data['ou']:
            qs = qs.filter(ou=data['ou'])
        try:
            self.user = qs.get()
        except User.DoesNotExist:
            raise serializers.ValidationError('no user found')
        except MultipleObjectsReturned:
            raise serializers.ValidationError('more than one user have this email')
        if not self.user.check_password(data['old_password']):
            raise serializers.ValidationError('old_password is invalid')
        return data


class PasswordChange(BaseRpcView):
    serializer_class = PasswordChangeSerializer

    def rpc(self, request, serializer):
        serializer.user.set_password(serializer.validated_data['new_password'])
        serializer.user.save()
        return {'result': 1}, status.HTTP_200_OK

password_change = PasswordChange.as_view()
