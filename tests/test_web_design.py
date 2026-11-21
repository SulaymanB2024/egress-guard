"""The web surfaces follow docs/design: one token set, the five type sizes, the spacing scale, no stray colour.

Shared drift test: a surface that adopts docs/design/tokens.css adds its stylesheet to ADOPTERS.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOKENS = ROOT / "docs" / "design" / "tokens.css"
WEB = ROOT / "src" / "egress_guard" / "web"
# Stylesheets that start with tokens.css byte for byte, followed by the surface's own rules.
ADOPTERS = [WEB / "app.css"]

# Every px literal outside the token block is on the spacing scale, a hairline, or a named spec dimension.
SCALE = {0, 1, 2, 4, 8, 12, 16, 24, 32, 48, 64}
NAMED_PX = {
    1.5: "chevron stroke, same as tokens .disclosure",
    6: "chevron size, same as tokens .disclosure",
    36: "tab height (DESIGN.md section 6, Tabs)",
    40: "one-line wide list row (section 6, List row)",
    56: "dashboard header bar and two-line phone row (mockup)",
    88: "Activity decision and time columns (section 2, Dashboard)",
    96: "bar strip height on phones (mockup)",
    120: "bar strip height (section 6, Bar strip, 24-120)",
    240: "Activity reason column (section 2, Dashboard)",
    320: "search field width (mockup)",
    560: "decision column, used for the confirmation dialog (section 2)",
    720: "single-column breakpoint (section 2)",
    1216: "container: 1152 content + 2 x 32 margins (section 2)",
}


def own_rules(path: Path) -> str:
    return path.read_text()[len(TOKENS.read_text()):]


def strip_comments(css: str) -> str:
    return re.sub(r"/\*.*?\*/", "", css, flags=re.S)


class TokenDriftTests(unittest.TestCase):
    def test_adopters_embed_tokens_byte_for_byte(self):
        tokens = TOKENS.read_bytes()
        for path in ADOPTERS:
            with self.subTest(path=path.name):
                self.assertTrue(path.read_bytes().startswith(tokens),
                                f"{path} must begin with docs/design/tokens.css unchanged; copy it again")


class DashboardStyleTests(unittest.TestCase):
    css = strip_comments(own_rules(WEB / "app.css"))

    def test_no_literal_colours_outside_tokens(self):
        self.assertEqual(re.findall(r"#[0-9a-fA-F]{3,8}\b|\b(?:rgba?|hsla?)\(", self.css), [])

    def test_px_values_are_on_the_scale_or_named(self):
        values = {float(value) for value in re.findall(r"(?<![\w.-])(\d+(?:\.\d+)?)px", self.css)}
        stray = sorted(value for value in values if value not in SCALE and value not in NAMED_PX)
        self.assertEqual(stray, [], "off-scale px values; use a token or name the dimension here")

    def test_type_comes_from_the_five_sizes(self):
        sizes = re.findall(r"font-size:\s*([^;}]+)", self.css)
        self.assertTrue(sizes)
        for size in sizes:
            self.assertRegex(size.strip(), r"^var\(--t-(caption|body|title|headline|display)\)$")
        self.assertEqual(re.findall(r"\bfont:(?!\s*inherit)[^;}]*", self.css), [])
        all_sizes = set(re.findall(r"--t-(\w+):", TOKENS.read_text()))
        self.assertLessEqual(len(all_sizes), 5)

    def test_one_primary_button_in_markup(self):
        html = (WEB / "index.html").read_text()
        self.assertLessEqual(html.count("btn primary"), 1)


class DashboardMarkupTests(unittest.TestCase):
    html = (WEB / "index.html").read_text()
    script = (WEB / "app.js").read_text()

    def test_every_element_the_script_reads_exists(self):
        ids = set(re.findall(r'\bid="([^"]+)"', self.html))
        used = set(re.findall(r"\$\('([^']+)'\)", self.script))
        self.assertEqual(sorted(used - ids), [])

    def test_tabs_follow_the_aria_pattern(self):
        tabs = re.findall(r'<button[^>]*role="tab"[^>]*>', self.html)
        self.assertEqual(len(tabs), 3)
        for tab in tabs:
            control = re.search(r'aria-controls="([^"]+)"', tab).group(1)
            self.assertRegex(self.html, rf'role="tabpanel" id="{control}" aria-labelledby=')
            self.assertIn("aria-selected=", tab)
        self.assertIn('role="tablist"', self.html)
        self.assertEqual(sum('aria-selected="true"' in tab for tab in tabs), 1)

    def test_no_inline_script_or_style(self):
        self.assertNotRegex(self.html, r"<script(?![^>]*\bsrc=)")
        self.assertNotRegex(self.html, r"<style|\sstyle=")
        self.assertNotIn("setAttribute('style'", self.script)
        self.assertNotIn("innerHTML", self.script)

    def test_threat_rows_never_offer_an_action(self):
        allow = re.search(r"if \(event\.decision === 'blocked' && \(category === 'ads' \|\| category === 'cname'\)", self.script)
        self.assertIsNotNone(allow)
        self.assertNotIn("category === 'threats') && durationOptions", self.script)


if __name__ == "__main__":
    unittest.main()
