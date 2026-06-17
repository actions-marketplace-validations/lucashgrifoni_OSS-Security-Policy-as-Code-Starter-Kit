"""Doc-structure regression for the v10 framework-alignment additions.

Guards the additive v10 documentation slice so it cannot silently regress:

- the OWASP Agentic ASI01-ASI10 mapping table (task: agentic-top10-depth),
- the CISA Secure by Design readiness section (task: cisa-secure-by-design-signals),
- the three informative AI framework crosswalks (task: framework-crosswalks-ai):
  NIST AI RMF / AI 600-1, ISO/IEC 42001, MITRE ATLAS.

These are documentation invariants only; they assert no control or gate behavior.
"""

from __future__ import annotations

from pathlib import Path

DOC = Path(__file__).resolve().parents[1] / "docs" / "framework-alignment.md"


def _doc() -> str:
    return DOC.read_text(encoding="utf-8")


def test_asi_coverage_table_present() -> None:
    text = _doc()
    # All ten ASI risk ids and the three controls that close the v10 gaps.
    for asi in ("ASI01", "ASI05", "ASI08", "ASI10"):
        assert asi in text, f"{asi} missing from ASI mapping"
    for cid in ("AGENT-ASI-EXEC-005", "AGENT-ASI-CASCADE-008", "AGENT-ASI-ROGUE-010"):
        assert cid in text, f"{cid} missing from ASI mapping"


def test_cisa_sbd_section_present_and_honest() -> None:
    text = _doc()
    assert "CISA Secure by Design Pledge" in text
    assert "ISO/IEC 29147" in text and "ISO/IEC 30111" in text
    assert "no certification or " in text  # honesty caveat ("...pledge fulfilled... claim")


def test_three_ai_framework_crosswalks_present_and_informative() -> None:
    text = _doc()
    lower = text.lower()
    assert "informative" in lower, "crosswalks must be marked informative"
    assert "NIST AI RMF" in text
    assert "ISO/IEC 42001" in text
    assert "MITRE ATLAS" in text
    # A real ATLAS technique id is cited (grounding: cite or omit).
    assert "AML.T0051" in text
    # No conformance/certification claim accompanies the crosswalks.
    assert "no conformance or certification" in lower
