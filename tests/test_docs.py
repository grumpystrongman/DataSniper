from pathlib import Path
from xml.etree import ElementTree

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "docs" / "assets"


def test_product_svg_assets_are_valid_xml():
    expected = {"logo.svg", "hero.svg", "dashboard.svg", "onboarding.svg", "demo.svg", "architecture.svg"}
    assert expected.issubset({path.name for path in ASSETS.glob("*.svg")})
    for name in expected:
        root = ElementTree.parse(ASSETS / name).getroot()
        assert root.tag.endswith("svg")
        assert root.attrib.get("viewBox")


def test_readme_references_existing_local_assets():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for relative in (
        "docs/assets/logo.svg",
        "docs/assets/hero.svg",
        "docs/assets/demo.svg",
        "docs/assets/dashboard.svg",
        "docs/assets/onboarding.svg",
        "docs/assets/architecture.svg",
    ):
        assert relative in readme
        assert (ROOT / relative).exists()


def test_landing_page_has_core_product_sections():
    page = (ROOT / "docs" / "index.html").read_text(encoding="utf-8")
    assert "Why DataSniper" in page
    assert "local-first" in page.lower()
    assert "Download from GitHub" in page
    assert 'id="product"' in page
    assert 'id="privacy"' in page
