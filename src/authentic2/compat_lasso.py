try:
    import lasso
except ImportError:
    class MockLasso(object):
        def __getattr__(self, key):
            if key[0].isupper():
                return ''
            return AttributeError('Please install lasso')
    lasso = MockLasso()
