"""Named detection policies loaded from config/policies/*.yaml."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List

import yaml
from loguru import logger

from config.settings import Settings, get_settings

POLICY_DIR = Path("config/policies")
_VALID_NAME = re.compile(r"^[A-Za-z0-9_-]{1,40}$")
# A policy can tighten detection freely, but only these keys may be overridden at all.
_ALLOWED_OVERRIDES = {
    "ml_classifier_threshold", "lexical_classifier_threshold", "intent_similarity_threshold",
    "agentic_trigger_flag_count", "agentic_trigger_severity", "agentic_soft_flag_rate",
    "warm_cache_flag_threshold", "warm_cache_high_threshold",
}


class ResolvedPolicy(Settings):
    policy_name: str = "default"
    policy_version: int = 1
    policy_description: str = "Global defaults"
    disabled_layers: List[str] = []
    extra_keywords: Dict[str, List[str]] = {}


def _defaults() -> dict:
    return get_settings().model_dump(by_alias=False)


def _build(values: dict) -> ResolvedPolicy:
    values = {k: v for k, v in values.items() if k != "frontend_urls"}
    return ResolvedPolicy(**values)


def load_policy(name: str) -> ResolvedPolicy:
    settings_dict = _defaults()
    if not name or name == "default":
        return _build(settings_dict)
    if not _VALID_NAME.match(name):  # blocks path traversal through a client-chosen name
        logger.warning("Rejected malformed policy name")
        return _build(settings_dict)
    policy_path = POLICY_DIR / f"{name}.yaml"
    if not policy_path.exists():
        return _build(settings_dict)
    try:
        policy_data = yaml.safe_load(policy_path.read_text(encoding="utf-8")) or {}
    except Exception:
        logger.warning(f"Policy {name} unreadable; using defaults")
        return _build(settings_dict)

    overrides = {k: v for k, v in (policy_data.get("overrides") or {}).items() if k in _ALLOWED_OVERRIDES}
    settings_dict.update(overrides)
    policy = _build(settings_dict)
    policy.policy_name = policy_data.get("name", name)
    policy.policy_version = policy_data.get("version", 1)
    policy.policy_description = policy_data.get("description", "")
    policy.disabled_layers = policy_data.get("disabled_layers", []) or []
    policy.extra_keywords = policy_data.get("extra_keywords", {}) or {}
    return policy


def _is_weaker(candidate: ResolvedPolicy, base: ResolvedPolicy) -> bool:
    if candidate.disabled_layers:
        return True
    for key in ("ml_classifier_threshold", "lexical_classifier_threshold", "intent_similarity_threshold",
                "agentic_trigger_flag_count", "agentic_trigger_severity", "warm_cache_flag_threshold"):
        if getattr(candidate, key) > getattr(base, key):
            return True
    return candidate.agentic_soft_flag_rate < base.agentic_soft_flag_rate


def resolve_policy_for_request(request) -> ResolvedPolicy:
    """A client may choose a policy only if it is at least as strict as the default."""
    from core.security.auth import is_admin_request

    name = request.headers.get("X-Heimdall-Policy", "default")
    policy = load_policy(name)
    if policy.policy_name != "default" and _is_weaker(policy, load_policy("default")):
        if not is_admin_request(request.headers.get("x-admin-key", "")):
            logger.warning("Rejected client request for a weaker policy")
            return load_policy("default")
    return policy
