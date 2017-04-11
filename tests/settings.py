import os

LANGUAGE_CODE = 'en'
DATABASES = {
    'default': {
        'ENGINE': os.environ.get('DB_ENGINE', 'django.db.backends.sqlite3'),
        'TEST': {
            'NAME': 'a2-test',
        },
    }
}
