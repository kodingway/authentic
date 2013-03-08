from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .nonce.models import Nonce
from models import User

class NonceModelAdmin(admin.ModelAdmin):
    list_display = ("value", "context", "not_on_or_after")

admin.site.register(Nonce, NonceModelAdmin)
admin.site.register(User, UserAdmin)
