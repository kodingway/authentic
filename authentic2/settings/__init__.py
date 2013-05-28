from common import *

try:
    from local_settings import *
except ImportError, e:
    if 'local_settings' in e.args[0]:
        pass

import auth_and_idp
