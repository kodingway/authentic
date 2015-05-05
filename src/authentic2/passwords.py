import string
import random

from . import app_settings

def generate_password():
    '''Generate a password that validates current password policy.

       Beware that A2_PASSWORD_POLICY_REGEX cannot be validated.
    '''
    digits = string.digits
    lower = string.lowercase
    upper = string.uppercase
    punc = string.punctuation

    min_len = max(app_settings.A2_PASSWORD_POLICY_MIN_LENGTH, 6)
    min_class_count = max(app_settings.A2_PASSWORD_POLICY_MIN_CLASSES, 2)
    new_password = []

    while len(new_password) < min_len:
        for cls in (digits, lower, upper, punc)[:min_class_count]:
            new_password.append(random.choice(cls))
    random.shuffle(new_password)
    return ''.join(new_password)

