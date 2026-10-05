import unittest
from unittest.mock import Mock
from requests import Response
from core.crawler import Crawler
from core.scope import ScopeValidator

class CrawlerTests(unittest.TestCase):
    def test_parse_page(self):
        client = Mock(); scope = ScopeValidator("http://127.0.0.1:3000/"); scope.validate_url()
        crawler = Crawler(client, scope)
        response = Response(); response.status_code=200; response.url="http://127.0.0.1:3000/"; response.headers["Content-Type"]="text/html"; response._content=b'<html><a href="/a?x=1">A</a><form method="POST" action="/save"><input name="q"></form></html>'
        ctx = crawler._parse_page(response, "http://127.0.0.1:3000/?x=1", 0)
        self.assertIn("q", ctx.form_fields)
        self.assertIn("x", ctx.parameters)

if __name__ == "__main__": unittest.main()
