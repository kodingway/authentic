from django.dispatch import Signal

'''authorize_decision
Expect a dictionnaries as return with:
 - the authorization decision e.g. dic['authz'] = True or False
 - optionnaly a message e.g. dic['message'] = message
'''
authorize_service = Signal(providing_args = ["request", "user", "audience",
        "attributes"])

'''avoid_consent
Expect a boolean e.g. dic['avoid_consent'] = True or False
'''
avoid_consent = Signal(providing_args = ["request", "user", "audience"])
