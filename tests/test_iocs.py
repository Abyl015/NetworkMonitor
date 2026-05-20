import sys
import tempfile
import unittest
from pathlib import Path

from NetworkMonitor.core.iocs import (
    load_domain_iocs,
    load_ip_iocs,
    match_domain_ioc,
    normalize_domain,
)


class IOCTestCase(unittest.TestCase):
    def _write_temp_ioc_file(self, content: str) -> Path:
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        file_path = Path(temp_dir.name) / "iocs.txt"
        file_path.write_text(content, encoding="utf-8")
        return file_path

    def test_ip_loader_ignores_empty_comments_and_strips_inline_comments(self):
        file_path = self._write_temp_ioc_file(
            "\n"
            "   \n"
            "# full-line comment\n"
            "  # indented full-line comment\n"
            " 192.0.2.10 \n"
            "198.51.100.5 # safe inline comment\n"
            "not-an-ip\n"
        )

        self.assertEqual(load_ip_iocs(file_path), {"192.0.2.10", "198.51.100.5"})

    def test_domain_loader_normalizes_lowercase_and_trailing_dot(self):
        file_path = self._write_temp_ioc_file(
            "# one domain per line\n"
            " BAD.EXAMPLE. \n"
            "Sub.Bad.Example. # safe inline comment\n"
        )

        self.assertEqual(load_domain_iocs(file_path), {"bad.example", "sub.bad.example"})

    def test_domain_match_exact(self):
        match = match_domain_ioc("bad.example", {"bad.example"})

        self.assertTrue(match.matched)
        self.assertEqual(match.value, "bad.example")

    def test_domain_match_safe_subdomain_suffix(self):
        match = match_domain_ioc("sub.bad.example.com", {"bad.example.com"})

        self.assertTrue(match.matched)
        self.assertEqual(match.value, "bad.example.com")

    def test_domain_match_rejects_unsafe_partial(self):
        match = match_domain_ioc("notbadexample.com", {"badexample.com"})

        self.assertFalse(match.matched)
        self.assertIsNone(match.value)

    def test_url_like_domain_normalization(self):
        self.assertEqual(
            normalize_domain("https://BAD.Example:8443/path?q=1"),
            "bad.example",
        )

    def test_enrichment_is_not_imported(self):
        self.assertNotIn("NetworkMonitor.core.enrichment", sys.modules)


if __name__ == "__main__":
    unittest.main()
