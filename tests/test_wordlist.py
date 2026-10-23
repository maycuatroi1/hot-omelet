"""Unit tests for pure helper functions in smart_wordlist and scanner_utils."""
import pytest

from hot_omelet.smart_wordlist import (
    SmartWordlist,
    extract_company_from_domain,
    extract_name_parts,
    leet_speak,
)
from hot_omelet.scanner_utils import normalize_target, tool_exists


# --- smart_wordlist helpers ---

class TestLeetSpeak:
    def test_basic_substitution(self):
        assert leet_speak("apple") == "@ppl3"

    def test_uppercase_letters(self):
        result = leet_speak("Apple")
        assert "@" in result and "3" in result

    def test_no_change_for_symbols(self):
        assert leet_speak("123") == "123"

    def test_empty(self):
        assert leet_speak("") == ""


class TestExtractCompanyFromDomain:
    def test_simple_domain(self):
        assert extract_company_from_domain("omelet.vn") == "omelet"

    def test_www_prefix_skipped(self):
        assert extract_company_from_domain("www.example.com") == "example"

    def test_mail_prefix_skipped(self):
        assert extract_company_from_domain("mail.corp.io") == "corp"

    def test_single_word(self):
        assert extract_company_from_domain("localhost") == "localhost"


class TestExtractNameParts:
    def test_dot_separated(self):
        parts = extract_name_parts("john.doe")
        assert "john" in parts
        assert "doe" in parts
        assert "johndoe" in parts
        assert "jdoe" in parts

    def test_single_name(self):
        parts = extract_name_parts("admin")
        assert "admin" in parts

    def test_strips_tld_tokens(self):
        parts = extract_name_parts("user.example.com")
        assert "com" not in parts
        assert "vn" not in parts

    def test_at_separated(self):
        parts = extract_name_parts("john@corp")
        assert "john" in parts
        assert "corp" in parts


class TestSmartWordlist:
    def test_generates_passwords(self):
        wl = SmartWordlist(company="acme", domain="acme.vn")
        result = wl.generate()
        assert len(result) > 0
        assert isinstance(result, list)

    def test_includes_global_weak(self):
        wl = SmartWordlist()
        result = wl.generate()
        assert "password" in result
        assert "admin" in result

    def test_company_based_passwords(self):
        wl = SmartWordlist(company="omelet", domain="omelet.vn")
        result = wl.generate()
        joined = " ".join(result)
        assert "omelet" in joined.lower()

    def test_auto_extract_company(self):
        wl = SmartWordlist(domain="acme.vn")
        assert wl.company == "acme"

    def test_max_passwords_limit(self):
        wl = SmartWordlist(company="test", domain="test.com", max_passwords=10)
        result = wl.generate()
        assert len(result) <= 10

    def test_save_to_file(self, tmp_path):
        wl = SmartWordlist(company="test")
        wl.generate()
        out = tmp_path / "wl.txt"
        wl.save(str(out))
        assert out.exists()
        assert out.read_text().strip()


# --- scanner_utils helpers ---

class TestNormalizeTarget:
    def test_strips_http_scheme(self):
        assert normalize_target("http://example.com") == "example.com"

    def test_strips_https_scheme(self):
        assert normalize_target("https://example.com") == "example.com"

    def test_plain_ip(self):
        assert normalize_target("192.168.1.1") == "192.168.1.1"

    def test_url_with_port(self):
        assert normalize_target("http://example.com:8080") == "example.com:8080"


class TestToolExists:
    def test_returns_bool(self):
        assert isinstance(tool_exists("python"), bool)

    def test_nonexistent_tool(self):
        assert tool_exists("this_tool_definitely_does_not_exist_xyz") is False
