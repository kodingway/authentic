from django.utils.translation import ugettext as _

from . import models, utils


def role_parenting_post_save(sender, instance, raw, created, **kwargs):
    '''Close the role parenting relation after instance creation'''
    if raw:  # do nothing if save comes from fixture loading
        return
    if not instance.direct:  # do nothing if instance is not direct
        return
    sender.objects.update_transitive_closure()


def role_parenting_post_delete(sender, instance, **kwargs):
    '''Close the role parenting relation after instance deletion'''
    if not instance.direct:  # do nothing if instance is not direct
        return
    sender.objects.update_transitive_closure()


def create_base_operations(**kwargs):
    '''Create some basic operations, matching permissions from Django'''
    utils.get_operation(models.ADD_OP)
    utils.get_operation(models.CHANGE_OP)
    utils.get_operation(models.DELETE_OP)
    utils.get_operation(models.VIEW_OP)
    utils.get_operation(models.ADMIN_OP)


def fix_role_parenting_closure(**kwargs):
    '''Close the role parenting relation after migrations'''
    utils.get_role_parenting_model().objects.update_transitive_closure()
