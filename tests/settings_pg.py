LANGUAGE_CODE = 'en'
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'TEST': {
            'NAME': 'a2-test',
        },
    }
}
