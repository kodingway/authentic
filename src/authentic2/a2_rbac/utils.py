from . import models

def get_default_ou():
    return models.OrganizationalUnit.objects.get(default=True)
