"""
LLM output validator for AEGIS-Recon.

Validates that AI-generated analysis meets schema requirements
and doesn't contain hallucinated data.

Checks:
1. Output is valid JSON matching the expected schema.
2. No CVE IDs appear that weren't in the input findings.
3. No command-like strings that could indicate prompt injection.
4. All required fields are present.
"""

from __future__ import annotations

import json
import re
from typing import Any

from app.core.errors import LLMValidationError
from app.core.logging import get_logger

logger = get_logger(__name__)

REQUIRED_KEYS = {"summary", "risk_overview", "recommendations", "limitations"}

# Patterns that suggest the LLM is trying to execute something
DANGEROUS_PATTERNS = [
    r"```bash",
    r"```shell",
    r"\bsudo\b",
    r"\bnmap\b.*-[a-zA-Z]",
    r"\bexploit\b.*\brun\b",
    r"\bmetasploit\b",
    r"\bmsfconsole\b",
    r"\bnc\s+-[a-z]",
    r"\bcurl\b.*\bhttp",
    r"\bwget\b",
]


def validate_ai_output(
    raw_output: str,
    input_cve_ids: set[str],
) -> dict[str, Any]:
    """
    Validate and parse LLM output.

    Args:
        raw_output: Raw string from the LLM.
        input_cve_ids: Set of CVE IDs that were provided in the prompt.

    Returns:
        Validated analysis dict.

    Raises:
        LLMValidationError: If output fails validation.
    """
    # Step 1: Parse JSON
    try:
        # Try to extract JSON from potential markdown wrapping
        cleaned = _extract_json(raw_output)
        data = json.loads(cleaned)
    except (json.JSONDecodeError, ValueError) as e:
        raise LLMValidationError(
            f"LLM output is not valid JSON: {e}",
            detail="Falling back to deterministic analysis.",
        )

    if not isinstance(data, dict):
        raise LLMValidationError("LLM output is not a JSON object.")

    # Step 2: Check required keys
    missing = REQUIRED_KEYS - set(data.keys())
    if missing:
        raise LLMValidationError(
            f"LLM output missing required fields: {missing}",
        )

    # Step 3: Check for hallucinated CVEs
    output_text = json.dumps(data)
    found_cves = set(re.findall(r"CVE-\d{4}-\d{4,}", output_text))
    hallucinated = found_cves - input_cve_ids

    if hallucinated:
        logger.warning(
            "llm_hallucinated_cves",
            hallucinated=list(hallucinated),
            count=len(hallucinated),
        )
        raise LLMValidationError(
            f"LLM output contains CVE IDs not in input data: {hallucinated}",
            detail="This may indicate hallucination. Using deterministic fallback.",
        )

    # Step 4: Check for dangerous content
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, output_text, re.IGNORECASE):
            logger.warning("llm_dangerous_content", pattern=pattern)
            raise LLMValidationError(
                "LLM output contains command-like content.",
                detail="Output appears to include executable instructions.",
            )

    # Step 5: Sanitize string values (length limits)
    data["summary"] = str(data.get("summary", ""))[:2000]
    data["risk_overview"] = str(data.get("risk_overview", ""))[:3000]
    data["limitations"] = str(data.get("limitations", ""))[:2000]
    data["confidence_notes"] = str(data.get("confidence_notes", ""))[:2000]

    if isinstance(data.get("recommendations"), list):
        data["recommendations"] = [str(r)[:500] for r in data["recommendations"][:20]]
    if isinstance(data.get("critical_findings"), list):
        data["critical_findings"] = [str(f)[:500] for f in data["critical_findings"][:20]]

    logger.info("llm_output_validated")
    return data


def _extract_json(text: str) -> str:
    """Extract JSON from potential markdown code block wrapping."""
    text = text.strip()

    # Remove markdown code fences
    if text.startswith("```"):
        lines = text.split("\n")
        # Remove first line (```json) and last line (```)
        if lines[-1].strip() == "```":
            lines = lines[1:-1]
        else:
            lines = lines[1:]
        text = "\n".join(lines).strip()

    # Find the JSON object boundaries
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        return text[start:end + 1]

    return text
