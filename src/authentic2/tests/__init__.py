import urlparse
from lxml import etree

from django.test import TestCase

from authentic2 import utils


def get_response_form(response, form='form'):
    contexts = list(response.context)
    for c in contexts:
        if form not in c:
            continue
        return c[form]


class Authentic2TestCase(TestCase):
    def assertEqualsURL(self, url1, url2, **kwargs):
        '''Check that url1 is equals to url2 augmented with parameters kwargs
           in its query string.

           The string '*' is a special value, when used it just check that the
           given parameter exist in the first url, it does not check the exact
           value.
        '''
        splitted1 = urlparse.urlsplit(url1)
        url2 = utils.make_url(url2, params=kwargs)
        splitted2 = urlparse.urlsplit(url2)
        for i, (elt1, elt2) in enumerate(zip(splitted1, splitted2)):
            if i == 3:
                elt1 = urlparse.parse_qs(elt1, True)
                elt2 = urlparse.parse_qs(elt2, True)
                for k, v in elt1.items():
                    elt1[k] = set(v)
                for k, v in elt2.items():
                    if v == ['*']:
                        elt2[k] = elt1.get(k, v)
                    else:
                        elt2[k] = set(v)
            self.assertTrue(
                elt1 == elt2,
                "URLs are not equal: %s != %s" % (splitted1, splitted2))

    def assertRedirectsComplex(self, response, expected_url, **kwargs):
        self.assertEquals(response.status_code, 302)
        scheme, netloc, path, query, fragment = urlparse.urlsplit(response.url)
        e_scheme, e_netloc, e_path, e_query, e_fragment = \
            urlparse.urlsplit(expected_url)
        e_scheme = e_scheme if e_scheme else scheme or 'http'
        e_netloc = e_netloc if e_netloc else netloc
        expected_url = urlparse.urlunsplit((e_scheme, e_netloc, e_path,
                                            e_query, e_fragment))
        self.assertEqualsURL(response['Location'], expected_url, **kwargs)

    def assertXPathConstraints(self, xml, constraints, namespaces):
        if hasattr(xml, 'content'):
            xml = xml.content
        doc = etree.fromstring(xml)
        for xpath, content in constraints:
            nodes = doc.xpath(xpath, namespaces=namespaces)
            self.assertTrue(len(nodes) > 0, 'xpath %s not found' % xpath)
            for node in nodes:
                if hasattr(node, 'text'):
                    self.assertEqual(
                        node.text, content, 'xpath %s does not contain %s but '
                        '%s' % (xpath, content, node.text))
                else:
                    self.assertEqual(
                        node, content, 'xpath %s does not contain %s but %s' %
                        (xpath, content, node))