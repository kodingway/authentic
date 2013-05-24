from django.db import models
from django.conf import settings

class OATHTOTPSecret(models.Model):
    user = models.OneToOneField(getattr(settings, 'AUTH_USER_MODEL', 'auth.User'),
            primary_key= True, related_name='oath_totp_secret')
    # 20 bytes string as hexadecimal
    key = models.CharField(max_length=40)
    drift = models.IntegerField(default=0,max_length=4)
