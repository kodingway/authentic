import xml.etree.ElementTree as ET

from utils import FancyTreeBuilder

class NS(object):
    AFP = 'urn:mace:shibboleth:2.0:afp'
    BASIC = 'urn:mace:shibboleth:2.0:afp:mf:basic'
    SAML = 'urn:mace:shibboleth:2.0:afp:mf:saml'
    XSI = 'http://www.w3.org/2001/XMLSchema-instance'

    # QName
    AF_POLICY_GROUP = '{%s}AttributeFilterPolicyGroup' % AFP
    AF_POLICY = '{%s}AttributeFilterPolicy' % AFP
    AF_POLICY_REQUIREMENT_RULE = '{%s}PolicyRequirementRule' % AFP
    AF_ATTRIBUTE_RULE = '{%s}AttributeRule' % AFP
    AF_PERMIT_VALUE_RULE = '{%s}PermitValueRule' % AFP
    XSI_TYPE = '{%s}type' % XSI
    ATTRIBUTE_REQUESTER_STRING = '{%s}AttributeRequesterString' % BASIC
    ANY = '{%s}ANY' % BASIC

    # attributes
    VALUE = 'value'
    IGNORECASE = 'ignoreCase'
    ATTRIBUTE_ID = 'attributeID'
    ID = 'id'

def parse_attribute_filters_file(path):
    tree = ET.parse(path, FancyTreeBuilder(target=ET.TreeBuilder()))
    root = tree.getroot()
    return parse_attribute_filter_et(root)

def fixqname(element, qname):
    prefix, local = qname.split(":")
    try:
        return "{%s}%s" % (element.namespaces[prefix], local)
    except KeyError:
        raise SyntaxError("unknown namespace prefix (%s)" % prefix)

def parse_attribute_filter_et(root):
    assert root.tag == NS.AF_POLICY_GROUP
    d = {}
    for child in root:
        assert child.tag == NS.AF_POLICY
        sub_children = list(child)
        prr = sub_children[0]
        assert prr.tag == NS.AF_POLICY_REQUIREMENT_RULE
        assert NS.XSI_TYPE in prr.attrib
        assert fixqname(prr, prr.attrib[NS.XSI_TYPE]) == NS.ATTRIBUTE_REQUESTER_STRING
        assert NS.VALUE in prr.attrib
        b = d[prr.attrib[NS.VALUE]] = []
        for sub_child in sub_children[1:]:
            assert sub_child.tag == NS.AF_ATTRIBUTE_RULE
            assert NS.ATTRIBUTE_ID in sub_child.attrib
            attribute_id = sub_child.attrib[NS.ATTRIBUTE_ID]
            assert len(list(sub_child)) == 1
            pvr = list(sub_child)[0]
            assert list(sub_child)[0].tag == NS.AF_PERMIT_VALUE_RULE
            assert NS.XSI_TYPE in pvr.attrib
            assert fixqname(pvr, pvr.attrib[NS.XSI_TYPE]) == NS.ANY
            b.append(attribute_id)
    return d


if __name__ == '__main__':
    import sys

    for key, values in parse_attribute_filters_file(sys.argv[1]).iteritems():
        print '-', key, ':'
        for value in values:
            print ' *', value
