class Service(object):
    url = None
    name = None
    actions = []

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

def get_username(user):
    '''Retrieve the username from a user model'''
    if hasattr(user, 'USERNAME_FIELD'):
        return getattr(user, user.USERNAME_FIELD)
    else:
        return user.username
