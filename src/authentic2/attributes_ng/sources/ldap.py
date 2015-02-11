from ...decorators import to_list

from authentic2.backends.ldap_backend import LDAPBackend, LDAPUser

@to_list
def get_instances(ctx):
    '''
    Retrieve instances from settings
    '''
    return [None]

def get_attribute_names(instance, ctx):
    return LDAPBackend.get_attribute_names()

def get_dependencies(instance, ctx):
    return ('user',)

def get_attributes(instance, ctx):
    user = ctx.get('user')
    if user and isinstance(user, LDAPUser):
        ctx.update(user.get_attributes())
    return ctx
