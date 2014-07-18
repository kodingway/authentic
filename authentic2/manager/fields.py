from django_select2 import AutoSelect2Field, NO_ERR_RESP

from . import utils

class ChooseUserField(AutoSelect2Field):
    def security_check(self, request, *args, **kwargs):
        return True

    def get_results(self, request, term, page, context):
        return (NO_ERR_RESP, False, [(u.ref, u.name) for u in utils.search_user(term)])

    def get_val_txt(self, value):
        """
        The problem of issue #66 was here. I was not overriding this.
        When using AutoSelect2MultipleField you should implement get_val_txt in this case.
        I think that this is because there should be an unique correspondence between
        the referenced value and the shown value
        In this particular example, the referenced value and the shown value are the same
        """
        return unicode(value)
