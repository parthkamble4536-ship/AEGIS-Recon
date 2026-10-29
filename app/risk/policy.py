"""
Risk policy loader for AEGIS-Recon Risk Engine V2.

Loads and validates the risk scoring policy from configs/risk_policy.yaml.
Falls back to built-in defaults when the file is missing or malformed.
"""

from __future__ import annotations

from pathlib import Path

from app.core.logging import get_logger
from app.risk.models import RiskPolicyWeights

logger = get_logger(__name__)

_DEFAULT_POLICY_PATH = Path(__file__).parent.parent.parent / "configs" / "risk_policy.yaml"


def load_policy(policy_path: Path | None = None) -> RiskPolicyWeights:
    """
    Load risk scoring policy from YAML file.

    Falls back to built-in defaults if the file doesn't exist or is malformed.

    Args:
        policy_path: Optional path override. Defaults to configs/risk_policy.yaml.

    Returns:
        RiskPolicyWeights with values from YAML or defaults.
    """
    path = policy_path or _DEFAULT_POLICY_PATH

    if not path.exists():
        logger.info("risk_policy_using_defaults", reason="file_not_found", path=str(path))
        return RiskPolicyWeights()

    try:
        import yaml  # type: ignore[import-untyped]

        with path.open() as f:
            data = yaml.safe_load(f) or {}

        weights = RiskPolicyWeights()
        # Apply any values present in the YAML (unknown keys are silently ignored)
        for field_name in RiskPolicyWeights.__dataclass_fields__:
            if field_name in data:
                setattr(weights, field_name, data[field_name])

        logger.info(
            "risk_policy_loaded",
            path=str(path),
            version=weights.policy_version,
            name=weights.policy_name,
        )
        return weights

    except ImportError:
        logger.warning("risk_policy_yaml_not_available", fallback="defaults")
        return RiskPolicyWeights()

    except Exception as exc:  # noqa: BLE001
        logger.warning("risk_policy_load_failed", error=str(exc), fallback="defaults")
        return RiskPolicyWeights()

