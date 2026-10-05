import unittest
from core.scope import ScopeValidator

class ScopeTests(unittest.TestCase):
    def test_same_origin(self):
        s = ScopeValidator("http://127.0.0.1:3000/")
        self.assertTrue(s.validate_url())
        self.assertTrue(s.is_in_scope("http://127.0.0.1:3000/a")[0])
    def test_external(self):
        s = ScopeValidator("http://127.0.0.1:3000/")
        s.validate_url()
        self.assertFalse(s.is_in_scope("https://example.com")[0])

if __name__ == "__main__": unittest.main()
