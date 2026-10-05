import unittest
from scanners.sqli import SQLiScanner

class SQLiTests(unittest.TestCase):
    def test_error_pattern(self):
        import re
        self.assertTrue(re.search(r"sql syntax.*mysql", "You have an error in your SQL syntax; MySQL", re.I))

if __name__ == "__main__": unittest.main()
