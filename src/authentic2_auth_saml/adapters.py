import logging

from mellon.adapters import DefaultAdapter
from mellon.utils import get_setting


class AuthenticAdapter(DefaultAdapter):
    def create_user(self, user_class):
        return user_class.objects.create()

    def finish_create_user(self, idp, saml_attributes, user):
        '''Copy incoming SAML attributes to user attributes, A2_ATTRIBUTE_MAPPING must be a list of
           dictinnaries like:

              {
                  'attribute': 'email',
                  'saml_attribute': 'email',
                  # optional:
                  'mandatory': False,
              }

            If an attribute is not mandatory any error is just logged, if the attribute is
            mandatory, login will fail.
        '''
        log = logging.getLogger(__name__)

        attribute_mapping = get_setting(idp, 'A2_ATTRIBUTE_MAPPING', [])
        for mapping in attribute_mapping:
            attribute = mapping['attribute']
            saml_attribute = mapping['saml_attribute']
            mandatory = mapping.get('mandatory', False)
            if not saml_attributes.get(saml_attribute):
                if mandatory:
                    log.error('mandatory saml attribute %r is missing', saml_attribute,
                              extra={'attributes': repr(saml_attributes)})
                    raise ValueError('missing attribute')
                else:
                    continue
            try:
                value = saml_attributes[saml_attribute]
                self.set_user_attribute(user, attribute, value)
            except Exception, e:
                log.error(u'failed to set attribute %r from saml attribute %r with value %r: %s',
                          attribute, saml_attribute, value, e,
                          extra={'attributes': repr(saml_attributes)})
                if mandatory:
                    raise

    def set_user_attribute(self, user, attribute, value):
        if isinstance(value, list):
            if len(value) > 1:
                raise ValueError('too much values')
            value = value[0]
        if attribute in ('first_name', 'last_name', 'email', 'username'):
            setattr(user, attribute, value)
        else:
            setattr(user.attributes, attribute, value)
