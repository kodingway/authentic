from django.contrib.auth import authenticate
from django.contrib.auth import login
from registration.backends.simple import SimpleBackend as OldSimpleBackend
from registration import signals


from authentic2.compat import get_user_model


class SimpleBackend(OldSimpleBackend):
    def register(self, request, **kwargs):
        """
        Create and immediately log in a new user.
        """
        create_kwargs = {
                'username': kwargs['username'],
                'email': kwargs['email'], 
                'password': kwargs['password1']
        }
        for required_field in get_user_model().REQUIRED_FIELDS:
            create_kwargs[required_field] = kwargs[required_field]
        get_user_model().objects.create_user(**create_kwargs)

        # authenticate() always has to be called before login(), and
        # will return the user we just created.
        new_user = authenticate(username=create_kwargs['username'], password=create_kwargs['password'])
        login(request, new_user)
        signals.user_registered.send(sender=self.__class__,
                                     user=new_user,
                                     request=request)
        return new_user
