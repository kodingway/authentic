import os

LANGUAGE_CODE = 'en'
DATABASES = {
    'default': {
        'ENGINE': os.environ['DB_ENGINE'],
        'TEST': {
            'NAME': 'a2-test',
        },
    }
}
