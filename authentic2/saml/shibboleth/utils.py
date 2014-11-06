import xml.etree.ElementTree as ET
from xml.etree.ElementTree import XMLTreeBuilder


class FancyTreeBuilder(XMLTreeBuilder):
    """Attach defined namespaces to elements during parsing"""

    def __init__(self, *args, **kwargs):
        super(FancyTreeBuilder, self).__init__(*args, **kwargs)
        self._namespaces = {}
        self._parser.StartNamespaceDeclHandler = self._start_ns


    def _start(self, *args):
        elem = super(FancyTreeBuilder, self)._start(*args)
        elem.namespaces = self._namespaces.copy()
        return elem

    def _start_list(self, *args):
        elem = super(FancyTreeBuilder, self)._start_list(*args)
        elem.namespaces = self._namespaces.copy()
        return elem

    def _start_ns(self, prefix, uri):
        self._namespaces[prefix] = uri

