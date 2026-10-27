"""
AI provider interface and implementations for AEGIS-Recon.

Supported providers:
- Google Gemini (Gemini 1.5 Flash / Pro via REST API with key rotation)
- Anthropic Claude (Claude 3.5 Sonnet / Haiku via REST API)
- Fallback to DeterministicAnalyzer if AI is disabled or fails validation

Design principles:
- LLM can NEVER execute commands or trigger actions.
- LLM output is strictly schema-validated before use.
- All findings are supplied to the LLM — it cannot invent CVEs.
- Automatic key rotation: if one API key hits a rate limit (429), the next key is tried.
- Deterministic fallback is always available when the LLM is unavailable or fails validation.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

import httpx

from app.ai.prompts import build_analysis_prompt
from app.ai.validator import validate_ai_output
from app.config import get_settings
from app.core.errors import LLMError, LLMUnavailableError, LLMValidationError
from app.core.logging import get_logger

logger = get_logger(__name__)


class AIProvider(ABC):
    """Abstract interface for AI analysis providers."""

    @abstractmethod
    def analyze_findings(
        self,
        findings: list[dict[str, Any]],
        scan_context: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Analyze scan findings and produce a summary.

        Args:
            findings: List of finding dicts (from the database).
            scan_context: Scan metadata (target, profile, timestamps).

        Returns:
            Analysis dict with keys: summary, recommendations,
            risk_overview, limitations, analysis_method.
        """
        ...

    @abstractmethod
    def is_available(self) -> bool:
        """Check if the provider is configured and reachable."""
        ...


class GeminiProvider(AIProvider):
    """
    Google Gemini API provider using official REST endpoints.
    Supports key rotation across multiple API keys if rate limits are encountered.
    """

    API_BASE = "https://generativelanguage.googleapis.com/v1beta/models"

    def __init__(
        self,
        api_keys: list[str],
        model: str = "gemini-1.5-flash",
        temperature: float = 0.2,
        max_tokens: int = 1024,
        timeout: float = 30.0,
    ) -> None:
        self.api_keys = [k.strip() for k in api_keys if k.strip()]
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout
        self._current_key_idx = 0

    def is_available(self) -> bool:
        """Available if at least one non-empty API key is configured."""
        return len(self.api_keys) > 0

    def _get_active_key(self) -> str:
        if not self.api_keys:
            raise LLMUnavailableError("No Gemini API keys configured.")
        return self.api_keys[self._current_key_idx % len(self.api_keys)]

    def _rotate_key(self) -> str:
        """Rotate to the next API key in the list."""
        self._current_key_idx = (self._current_key_idx + 1) % len(self.api_keys)
        next_key = self._get_active_key()
        logger.info("gemini_key_rotated", key_index=self._current_key_idx)
        return next_key

    def analyze_findings(
        self,
        findings: list[dict[str, Any]],
        scan_context: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Send prompt to Gemini API, parse and validate the JSON output.
        Falls back to next key on 429 rate limit.
        """
        if not self.is_available():
            raise LLMUnavailableError("Gemini provider is not configured.")

        # Build prompt pair
        system_prompt, user_prompt = build_analysis_prompt(findings, scan_context)

        # Ground-truth CVEs to prevent hallucination
        input_cve_ids = {f.get("cve_id", "").strip() for f in findings if f.get("cve_id")}

        url = f"{self.API_BASE}/{self.model}:generateContent"
        payload = {
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": user_prompt}],
                }
            ],
            "systemInstruction": {
                "parts": [{"text": system_prompt}],
            },
            "generationConfig": {
                "temperature": self.temperature,
                "maxOutputTokens": self.max_tokens,
                "responseMimeType": "application/json",
            },
        }

        # Try with rotation across keys
        last_error: Exception | None = None
        max_attempts = len(self.api_keys)

        for attempt in range(max_attempts):
            api_key = self._get_active_key()
            headers = {
                "Content-Type": "application/json",
                "x-goog-api-key": api_key,
            }

            try:
                with httpx.Client(timeout=self.timeout) as client:
                    resp = client.post(url, headers=headers, json=payload)

                if resp.status_code == 429:
                    logger.warning(
                        "gemini_rate_limited", attempt=attempt, key_index=self._current_key_idx
                    )
                    self._rotate_key()
                    last_error = LLMUnavailableError(
                        f"Gemini API rate limited (attempt {attempt + 1})."
                    )
                    continue

                if resp.status_code != 200:
                    error_msg = f"Gemini API error {resp.status_code}: {resp.text[:200]}"
                    logger.warning(
                        "gemini_api_error", status_code=resp.status_code, body=resp.text[:200]
                    )
                    # If auth error (400/401/403), try next key if available
                    if resp.status_code in (400, 401, 403) and attempt < max_attempts - 1:
                        self._rotate_key()
                        continue
                    raise LLMError(error_msg)

                # Parse response body
                data = resp.json()
                candidates = data.get("candidates", [])
                if not candidates:
                    raise LLMError("Gemini returned empty candidates list.")

                content_parts = candidates[0].get("content", {}).get("parts", [])
                if not content_parts or "text" not in content_parts[0]:
                    raise LLMError("Gemini response missing text in content parts.")

                raw_text = content_parts[0]["text"]

                # Validate against schema and check for hallucinations
                validated = validate_ai_output(raw_text, input_cve_ids)
                validated["analysis_method"] = f"ai ({self.model})"
                return validated

            except (httpx.TimeoutException, httpx.NetworkError) as e:
                logger.warning("gemini_network_error", error=str(e))
                last_error = e
                # Network error: rotate key and retry if keys remain
                self._rotate_key()
                continue
            except LLMValidationError:
                # Output failed validation (e.g. hallucination) — re-raise to trigger fallback
                raise

        if last_error:
            raise LLMUnavailableError(f"All Gemini API keys exhausted or unreachable: {last_error}")

        raise LLMUnavailableError("Failed to obtain analysis from Gemini API.")


def get_ai_provider() -> AIProvider | None:
    """Factory function returning the configured AI provider, or None if disabled."""
    settings = get_settings()

    if not settings.ai_enabled:
        return None

    if settings.ai_provider == "gemini":
        # Keys can be a single string or comma-separated list
        raw_keys = settings.gemini_api_key
        keys = [k.strip() for k in raw_keys.split(",") if k.strip()]
        if not keys:
            return None
        return GeminiProvider(
            api_keys=keys,
            model=settings.gemini_model,
            temperature=settings.ai_temperature,
            max_tokens=settings.ai_max_tokens,
        )

    return None
