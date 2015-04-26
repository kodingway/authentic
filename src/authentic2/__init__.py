import sys
import os

# vendor contains incorporated dependencies
sys.path.append(os.path.join(os.path.dirname(__file__), 'vendor'))

default_app_config = 'authentic2.apps.Authentic2Config'
