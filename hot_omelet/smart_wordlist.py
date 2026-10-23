"""
Smart contextual password generator.

Generates password candidates based on intelligence gathered during
reconnaissance: company name, domain, employee names, discovered
usernames, email patterns, etc.

Usage:
    from hot_omelet.smart_wordlist import SmartWordlist

    wl = SmartWordlist(
        company="omelet",
        domain="omelet.vn",
        usernames=["admin", "john.doe", "jdoe"],
        emails=["admin@omelet.vn", "john@omelet.vn"],
        extra_keywords=["hanoi", "2024"],
    )
    passwords = wl.generate()
    wl.save("./workers/10.1.0.8/smart_wordlist.txt")

CLI:
    python -m hot_omelet.smart_wordlist --company omelet --domain omelet.vn \
        --usernames admin,john.doe --output wordlist.txt
"""

import re
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Set


# Common suffixes Vietnamese companies/users love
NUMERIC_SUFFIXES = [
    "", "1", "12", "123", "1234", "12345", "123456",
    "!@#", "!@#$", "@123", "@1234", "@12345", "@123456",
    "#123", "$123", "!123", "!1234",
]

YEAR_SUFFIXES = []  # populated dynamically

SPECIAL_SUFFIXES = [
    "@", "!", "#", "$", "*", "@@", "!!", "##",
    "@!", "!@", "@#", "#$", "!@#", "@!@",
]

COMMON_PATTERNS = [
    # Vietnamese-style patterns
    "{word}@123", "{word}@1234", "{word}@12345", "{word}@123456",
    "{word}123", "{word}1234", "{word}12345", "{word}123456",
    "{word}!", "{word}!!", "{word}@", "{word}@@",
    "{word}#123", "{word}$123",
    "{Word}@123", "{Word}@1234", "{Word}@12345",
    "{Word}123", "{Word}1234", "{Word}12345",
    "{WORD}@123", "{WORD}@1234", "{WORD}@12345",
    "{WORD}123", "{WORD}1234",
    # Year-based
    "{word}@{year}", "{word}{year}", "{Word}@{year}", "{Word}{year}",
    "{word}@{yr}", "{word}{yr}", "{Word}@{yr}",
    "{word}@{year}!", "{word}{year}!", "{Word}@{year}!",
    # Leet speak
    "{l33t}@123", "{l33t}123", "{l33t}@{year}",
    # Reversed
    "{rev}@123", "{rev}123",
    # With separator
    "{word}.123", "{word}_123", "{word}-123",
    "{word}.{year}", "{word}_{year}", "{word}-{year}",
]

# Globally common weak passwords (always include)
GLOBAL_WEAK = [
    "password", "Password", "Password1", "Password@1",
    "password1", "password123", "password@123",
    "P@ssw0rd", "P@ssword1", "P@ssw0rd!",
    "admin", "Admin", "admin123", "Admin@123", "Admin123",
    "root", "Root", "root123", "Root@123",
    "welcome", "Welcome", "Welcome1", "Welcome@1",
    "qwerty", "Qwerty", "qwerty123", "Qwerty@123",
    "letmein", "changeme", "master",
    "abc123", "abc@123", "Abc@123", "ABC@123",
    "test", "test123", "Test@123",
    "123456", "1234567", "12345678", "123456789",
    "1q2w3e4r", "1q2w3e4r5t", "1qaz2wsx",
    "!@#$%^&*", "Aa@123456", "Aa123456",
    # Vietnamese common
    "matkhau", "matkhau123", "Matkhau@123",
    "mk123456", "mk@123456",
    "anhyeuem", "iloveyou",
]


def leet_speak(word: str) -> str:
    """Convert word to basic leet speak."""
    table = str.maketrans("aAeEiIoOsStT", "@@33!!00$$++" )
    return word.translate(table)


def extract_company_from_domain(domain: str) -> str:
    """Extract company name from domain (omelet.vn -> omelet)."""
    parts = domain.split(".")
    if len(parts) >= 2:
        name = parts[0]
        # Skip www, mail, etc.
        if name in ("www", "mail", "ftp", "smtp", "pop", "imap", "ns1", "ns2"):
            name = parts[1] if len(parts) > 2 else parts[0]
        return name
    return domain


def extract_name_parts(full_name: str) -> List[str]:
    """Extract parts from a name (john.doe -> [john, doe, johndoe, jdoe, john.doe])."""
    parts = re.split(r"[._\-@\s]", full_name.lower())
    parts = [p for p in parts if p and p not in ("com", "vn", "net", "org", "io")]
    results = list(parts)

    if len(parts) >= 2:
        # Concatenated
        results.append("".join(parts))
        # First initial + last
        results.append(parts[0][0] + parts[-1])
        # First + last initial
        results.append(parts[0] + parts[-1][0])
        # Last + first
        results.append(parts[-1] + parts[0])

    return list(set(results))


class SmartWordlist:
    """Generate contextual password candidates from gathered intelligence."""

    def __init__(
        self,
        company: Optional[str] = None,
        domain: Optional[str] = None,
        usernames: Optional[List[str]] = None,
        emails: Optional[List[str]] = None,
        employee_names: Optional[List[str]] = None,
        extra_keywords: Optional[List[str]] = None,
        years: Optional[List[str]] = None,
        max_passwords: int = 5000,
    ):
        self.company = company
        self.domain = domain
        self.usernames = usernames or []
        self.emails = emails or []
        self.employee_names = employee_names or []
        self.extra_keywords = extra_keywords or []
        self.max_passwords = max_passwords

        # Auto-extract company from domain if not provided
        if not self.company and self.domain:
            self.company = extract_company_from_domain(self.domain)

        # Years to use
        now = datetime.now()
        self.years = years or [
            str(now.year - 1), str(now.year), str(now.year + 1),
            str(now.year)[-2:], str(now.year - 1)[-2:],
        ]

        self._passwords: Set[str] = set()

    def _add_word_mutations(self, word: str):
        """Generate all mutations for a single base word."""
        if not word or len(word) < 2:
            return

        variants = {
            "word": word.lower(),
            "Word": word.capitalize(),
            "WORD": word.upper(),
            "l33t": leet_speak(word.lower()),
            "rev": word.lower()[::-1],
        }

        for year in self.years:
            for pattern in COMMON_PATTERNS:
                try:
                    pwd = pattern.format(
                        **variants,
                        year=year,
                        yr=year[-2:] if len(year) == 4 else year,
                    )
                    if 4 <= len(pwd) <= 32:
                        self._passwords.add(pwd)
                except (KeyError, IndexError):
                    continue

        # Direct numeric suffixes
        for suffix in NUMERIC_SUFFIXES:
            for base in [variants["word"], variants["Word"], variants["WORD"]]:
                pwd = base + suffix
                if 4 <= len(pwd) <= 32:
                    self._passwords.add(pwd)

    def generate(self) -> List[str]:
        """Generate the full password list."""
        # 1. Always include global weak passwords
        self._passwords.update(GLOBAL_WEAK)

        # 2. Company name mutations
        if self.company:
            self._add_word_mutations(self.company)
            # Company + common words
            for suffix in ["admin", "user", "test", "dev", "prod", "server"]:
                self._add_word_mutations(self.company + suffix)
                self._add_word_mutations(suffix + self.company)

        # 3. Domain mutations
        if self.domain:
            domain_name = extract_company_from_domain(self.domain)
            if domain_name != self.company:
                self._add_word_mutations(domain_name)

        # 4. Username mutations
        for username in self.usernames:
            self._add_word_mutations(username)
            for part in extract_name_parts(username):
                self._add_word_mutations(part)

        # 5. Email-based mutations
        for email in self.emails:
            local_part = email.split("@")[0] if "@" in email else email
            self._add_word_mutations(local_part)
            for part in extract_name_parts(local_part):
                self._add_word_mutations(part)

        # 6. Employee name mutations
        for name in self.employee_names:
            for part in extract_name_parts(name):
                self._add_word_mutations(part)

        # 7. Extra keywords
        for kw in self.extra_keywords:
            self._add_word_mutations(kw)

        # 8. Cross-combinations (company + username patterns)
        if self.company and self.usernames:
            for username in self.usernames[:5]:  # limit to avoid explosion
                parts = extract_name_parts(username)
                for part in parts[:3]:
                    combo = self.company + part
                    self._add_word_mutations(combo)

        # Sort and limit
        result = sorted(self._passwords)
        if len(result) > self.max_passwords:
            result = result[: self.max_passwords]

        return result

    def save(self, output_path: str) -> str:
        """Generate and save wordlist to file."""
        passwords = self.generate()
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(passwords) + "\n")
        return str(path)

    def save_cred_pairs(self, output_path: str, usernames: Optional[List[str]] = None) -> str:
        """Generate user:password pairs for credential stuffing."""
        passwords = self.generate()
        users = usernames or self.usernames or ["admin", "root", "user"]

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        pairs = []
        for user in users:
            for pwd in passwords:
                pairs.append(f"{user}:{pwd}")

        path.write_text("\n".join(pairs) + "\n")
        return str(path)

    def stats(self) -> dict:
        """Return generation statistics."""
        passwords = self.generate()
        return {
            "total_passwords": len(passwords),
            "company": self.company,
            "domain": self.domain,
            "usernames_used": len(self.usernames),
            "emails_used": len(self.emails),
            "employees_used": len(self.employee_names),
            "extra_keywords": len(self.extra_keywords),
            "sample": passwords[:20],
        }


def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Smart contextual password generator"
    )
    parser.add_argument("--company", "-c", help="Company name")
    parser.add_argument("--domain", "-d", help="Target domain")
    parser.add_argument("--usernames", "-u", help="Comma-separated usernames")
    parser.add_argument("--emails", "-e", help="Comma-separated emails")
    parser.add_argument("--names", "-n", help="Comma-separated employee names")
    parser.add_argument("--keywords", "-k", help="Comma-separated extra keywords")
    parser.add_argument("--output", "-o", default="smart_wordlist.txt", help="Output file")
    parser.add_argument("--max", "-m", type=int, default=5000, help="Max passwords")
    parser.add_argument("--pairs", "-p", action="store_true", help="Output user:pass pairs")
    parser.add_argument("--stats", "-s", action="store_true", help="Show stats only")

    args = parser.parse_args()

    wl = SmartWordlist(
        company=args.company,
        domain=args.domain,
        usernames=args.usernames.split(",") if args.usernames else [],
        emails=args.emails.split(",") if args.emails else [],
        employee_names=args.names.split(",") if args.names else [],
        extra_keywords=args.keywords.split(",") if args.keywords else [],
        max_passwords=args.max,
    )

    if args.stats:
        import json
        print(json.dumps(wl.stats(), indent=2))
        return

    if args.pairs:
        path = wl.save_cred_pairs(args.output)
    else:
        path = wl.save(args.output)

    passwords = wl.generate()
    print(f"Generated {len(passwords)} passwords -> {path}")
    print(f"Sample: {passwords[:10]}")


if __name__ == "__main__":
    main()
