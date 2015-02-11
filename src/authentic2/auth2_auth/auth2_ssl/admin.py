from django.contrib import admin

from . import models

class ClientCertificateAdmin(admin.ModelAdmin):
    list_display = ('user', 'subject_dn', 'issuer_dn', 'serial')

admin.site.register(models.ClientCertificate, ClientCertificateAdmin)
