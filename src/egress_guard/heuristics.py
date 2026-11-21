"""Small built-in host rules that complement the downloaded feeds.

Every entry here is fixed in the source, short and individually justified, so a reviewer can
read the whole rule set. None of it is fetched or changed at runtime.
"""

from __future__ import annotations

import unicodedata

# Exact hosts that no downloaded list may block. A bad upstream entry must not lock people out of
# signing in, installing operating-system updates or checking whether a certificate was revoked.
# Exact names only: a subdomain such as user-content hosting never inherits this protection.
# The user's own block rules still apply.
SAFETY_HOSTS = frozenset({
    # Apple: Apple Account sign-in and authentication.
    "appleid.apple.com", "idmsa.apple.com",
    # Apple: software-update catalogs, payloads and update personalization (signing).
    "swscan.apple.com", "swdist.apple.com", "mesu.apple.com", "updates.cdn-apple.com", "gs.apple.com",
    # Apple: certificate revocation (OCSP and CRL) for the system trust store and Developer ID.
    "ocsp.apple.com", "ocsp2.apple.com", "crl.apple.com", "valid.apple.com",
    # Google: account sign-in and OAuth token exchange used by every "Sign in with Google".
    "accounts.google.com", "oauth2.googleapis.com",
    # Google: Chrome and component updates.
    "dl.google.com", "update.googleapis.com",
    # Google Trust Services revocation.
    "ocsp.pki.goog", "crl.pki.goog",
    # Microsoft: Entra ID and personal-account sign-in.
    "login.microsoftonline.com", "login.live.com",
    # Microsoft: Office for Mac updates and Microsoft PKI revocation.
    "officecdnmac.microsoft.com", "oneocsp.microsoft.com",
    # DigiCert revocation, used by a large share of public web certificates.
    "ocsp.digicert.com", "crl3.digicert.com", "crl4.digicert.com",
    # Mozilla: Firefox application updates.
    "aus5.mozilla.org",
})

# Public resolver addresses that answer DNS-over-HTTPS. A client that cannot reach a DoH name
# may still try these by address, which a hostname feed cannot see.
DOH_RESOLVER_IPS = frozenset({
    "1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001",  # Cloudflare
    "8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844",  # Google Public DNS
    "9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9",  # Quad9
    "94.140.14.14", "94.140.15.15", "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff",  # AdGuard DNS
    "208.67.222.222", "208.67.220.220", "2620:119:35::35", "2620:119:53::53",  # OpenDNS
})

# Brand labels that are frequent homograph targets. Only labels of four or more characters are
# listed, so short words do not produce accidental matches.
LOOKALIKE_BRANDS = frozenset({
    "apple", "icloud", "google", "gmail", "youtube", "microsoft", "outlook", "office", "hotmail",
    "windows", "xbox", "amazon", "paypal", "facebook", "instagram", "whatsapp", "netflix", "github",
    "gitlab", "linkedin", "twitter", "dropbox", "adobe", "yahoo", "spotify", "steampowered",
    "steamcommunity", "coinbase", "binance", "kraken", "metamask", "chase", "wellsfargo",
    "bankofamerica", "hsbc", "barclays", "santander", "revolut", "venmo", "cashapp", "stripe",
    "shopify", "ebay", "walmart", "docusign", "zoom", "slack", "discord", "telegram", "openai",
    "chatgpt", "anthropic", "okta", "booking", "airbnb", "dhl", "fedex",
})

# Unicode letters that render like ASCII letters in common fonts (a subset of Unicode TR39
# confusables covering Cyrillic, Greek and Latin look-alikes). Accents are removed separately.
CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j",
    "ѕ": "s", "ԁ": "d", "һ": "h", "ӏ": "l", "ԛ": "q", "ԝ": "w", "к": "k", "ո": "n", "ս": "u",
    "α": "a", "ο": "o", "ν": "v", "ρ": "p", "ι": "i", "κ": "k", "υ": "u", "ε": "e", "τ": "t",
    "ı": "i", "ł": "l", "ɑ": "a", "ɡ": "g", "ɩ": "i", "ƅ": "b", "ɢ": "g", "ʟ": "l", "ꞵ": "b",
    "0": "o",
})


def _skeleton(text: str) -> str:
    decomposed = unicodedata.normalize("NFKD", text.lower())
    plain = "".join(char for char in decomposed if not unicodedata.combining(char))
    return plain.translate(CONFUSABLES)


def lookalike(host: str) -> tuple[str, str] | None:
    """Return (matched domain, imitated brand) for a punycode label that imitates a brand.

    A label matches when one of its hyphen-separated parts contains non-ASCII characters and,
    after removing accents and mapping look-alike letters, spells a listed brand. Plain ASCII
    parts never match, so `bücher-apple` is not a homograph of `apple`, but `аpple` is.
    """
    labels = host.split(".")
    for index, label in enumerate(labels):
        if not label.startswith("xn--"):
            continue
        try:
            text = label[4:].encode("ascii").decode("punycode")
        except (UnicodeError, ValueError):
            continue
        for part in text.split("-"):
            if not part.isascii() and (brand := _skeleton(part)) in LOOKALIKE_BRANDS:
                return ".".join(labels[index:]), brand
    return None
