from datetime import timedelta
import logging


from django.db import models
from django.utils.timezone import now


logger = logging.getLogger(__name__)

class DeletedUserManager(models.Manager):
    def delete_user(self, user):
        user.is_active = False
        user.save()
        self.create(user=user)

    def cleanup(self):
        '''Delete all deleted users for more than 10 minutes.'''
        not_after = now() - timedelta(seconds=600)
        for deleted_user in self.filter(creation__lte=not_after):
            user = deleted_user.user
            deleted_user.delete()
            user.delete()
            logger.info(u'deleted account %s' % user)
