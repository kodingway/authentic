import logging

class SettingsLogLevel(int):
    def __new__(cls, default_log_level, debug_setting='DEBUG'):
        return super(SettingsLogLevel, cls).__new__(
            cls, getattr(logging, default_log_level))

    def __init__(self, default_log_level, debug_setting='DEBUG'):
        self.debug_setting = debug_setting
        super(SettingsLogLevel, self).__init__(
            getattr(logging, default_log_level))

class DjangoLogger(logging.getLoggerClass()):
    def getEffectiveLevel(self):
        level = super(DjangoLogger, self).getEffectiveLevel()
        if isinstance(level, SettingsLogLevel):
            from django.conf import settings
            debug = getattr(settings, level.debug_setting, False)
            if debug:
                return logging.DEBUG
        return level

logging.setLoggerClass(DjangoLogger)

class DjangoRootLogger(DjangoLogger, logging.RootLogger):
    pass

logging.root.__class__ = DjangoRootLogger
