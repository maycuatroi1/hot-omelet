"""Categorised domain catalogue for DNS cache snooping.

Snooping a resolver's cache reveals which of these names other clients recently
resolved. Grouped by intent so an operator can target a context (banking, AI,
adult, corp SaaS, …) or merge everything. Extend `CATEGORIES` freely or pass a
custom wordlist file at the CLI.
"""
from __future__ import annotations

from typing import Iterable, List, Optional

CATEGORIES = {
    "banking_vn": [
        "vietcombank.com.vn", "techcombank.com.vn", "mbbank.com.vn", "acb.com.vn",
        "bidv.com.vn", "vietinbank.vn", "tpb.vn", "vpbank.com.vn", "sacombank.com.vn",
        "agribank.com.vn", "timo.vn", "cake.vn",
    ],
    "banking_global": [
        "paypal.com", "wise.com", "revolut.com", "chase.com", "hsbc.com",
        "citibank.com", "bankofamerica.com",
    ],
    "crypto": [
        "binance.com", "coinbase.com", "okx.com", "bybit.com", "kraken.com",
        "metamask.io", "remitano.com",
    ],
    "social": [
        "facebook.com", "instagram.com", "tiktok.com", "x.com", "twitter.com",
        "threads.net", "linkedin.com", "reddit.com", "pinterest.com",
    ],
    "messaging": [
        "zalo.me", "telegram.org", "web.telegram.org", "whatsapp.com", "messenger.com",
        "discord.com", "slack.com", "signal.org",
    ],
    "ai": [
        "openai.com", "chatgpt.com", "claude.ai", "anthropic.com", "gemini.google.com",
        "perplexity.ai", "copilot.microsoft.com", "huggingface.co", "midjourney.com",
    ],
    "shopping": [
        "shopee.vn", "lazada.vn", "tiki.vn", "sendo.vn", "amazon.com", "aliexpress.com",
        "thegioididong.com", "dienmayxanh.com",
    ],
    "streaming": [
        "youtube.com", "netflix.com", "spotify.com", "vieon.vn",
        "twitch.tv", "soundcloud.com",
    ],
    "adult": [
        "pornhub.com", "xvideos.com", "xnxx.com", "onlyfans.com",
    ],
    "cloud_saas": [
        "office.com", "microsoft.com", "google.com", "drive.google.com", "dropbox.com",
        "notion.so", "atlassian.net", "salesforce.com", "zoom.us", "okta.com",
    ],
    "dev": [
        "github.com", "gitlab.com", "bitbucket.org", "npmjs.com", "pypi.org",
        "docker.com", "hub.docker.com", "stackoverflow.com",
    ],
    "email": [
        "gmail.com", "mail.google.com", "outlook.com", "outlook.office365.com",
        "proton.me", "yahoo.com", "zoho.com",
    ],
    "apple": [
        "apple.com", "icloud.com", "itunes.apple.com",
    ],
    "infra": [  # vendor/management endpoints worth knowing a host phones home to
        "setup.ui.com", "unifi.ui.com", "teamviewer.com", "anydesk.com",
        "windowsupdate.com", "ubnt.com",
    ],
}

# A broad default mix across categories — good first pass for any open resolver.
DEFAULT = [
    "google.com", "facebook.com", "youtube.com", "tiktok.com", "instagram.com",
    "zalo.me", "telegram.org", "openai.com", "chatgpt.com", "claude.ai",
    "shopee.vn", "tiki.vn", "lazada.vn", "vnexpress.net",
    "github.com", "microsoft.com", "office.com", "apple.com", "icloud.com",
    "vietcombank.com.vn", "techcombank.com.vn", "mbbank.com.vn", "acb.com.vn",
    "binance.com", "netflix.com", "spotify.com", "pornhub.com", "setup.ui.com",
]


def build_list(categories: Optional[Iterable[str]] = None,
               extra: Optional[Iterable[str]] = None,
               wordlist_file: Optional[str] = None) -> List[str]:
    """Merge selected categories + a file + extras into a de-duplicated list.

    `categories`: names from CATEGORIES, or "all", or None -> DEFAULT mix.
    """
    domains: List[str] = []
    if wordlist_file:
        with open(wordlist_file) as f:
            domains += [line.strip() for line in f if line.strip() and not line.startswith("#")]
    if categories:
        cats = list(categories)
        if "all" in cats:
            for v in CATEGORIES.values():
                domains += v
        else:
            for c in cats:
                domains += CATEGORIES.get(c, [])
    if not categories and not wordlist_file:
        domains += DEFAULT
    if extra:
        domains += list(extra)
    seen, out = set(), []
    for d in domains:
        d = d.strip().rstrip(".")
        if d and d not in seen:
            seen.add(d)
            out.append(d)
    return out
