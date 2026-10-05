import unittest
from scanners.xss import XSSScanner

class XSSTests(unittest.TestCase):
    def test_marker(self):
        self.assertIn("VurnCheck", XSSScanner.MARKER)

if __name__ == "__main__": unittest.main()
