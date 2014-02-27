#!/usr/bin/python
from setuptools import setup, find_packages
import os

setup(name='authentic2-test-plugin',
        version='1.0',
        license='AGPLv3',
        description='Authentic2 Test Plugin',
        author="Entr'ouvert",
        author_email="info@entrouvert.com",
        packages=find_packages(os.path.dirname(__file__) or '.'),
        entry_points={
            'authentic2.plugin': [
                'test-plugin = a2_test_plugin:Plugin',
            ],
        },
)
