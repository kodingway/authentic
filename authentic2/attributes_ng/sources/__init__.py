import abc

class BaseAttributeSource(object):
    '''
    Base class for attribute sources
    '''
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def get_instances(self, ctx):
        pass

    @abc.abstractmethod
    def get_attribute_names(self, instance, ctx):
        pass

    @abc.abstractmethod
    def get_attributes(self, instance, ctx):
        pass

    @abc.abstractmethod
    def get_dependencies(self, instance, ctx):
        pass
