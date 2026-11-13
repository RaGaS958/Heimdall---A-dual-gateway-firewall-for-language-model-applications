import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any
from config.settings import get_settings, Settings

class ResolvedPolicy(Settings):
    policy_name: str = "default"
    policy_version: int = 1
    policy_description: str = "Global defaults"
    disabled_layers: List[str] = []
    extra_keywords: Dict[str, List[str]] = {}

def load_policy(name: str) -> ResolvedPolicy:
    if not name or name == "default":
        return ResolvedPolicy(**get_settings().model_dump())
    
    settings_dict = get_settings().model_dump()
    
    # Path to policy file
    policy_path = Path("config/policies") / f"{name}.yaml"
    if not policy_path.exists():
        return ResolvedPolicy(**settings_dict)
    
    try:
        with open(policy_path, "r") as f:
            policy_data = yaml.safe_load(f) or {}
    except Exception as e:
        return ResolvedPolicy(**settings_dict)

    # Merge overrides
    overrides = policy_data.get("overrides", {})
    settings_dict.update(overrides)
    
    # Create the resolved policy
    policy = ResolvedPolicy(**settings_dict)
    policy.policy_name = policy_data.get("name", name)
    policy.policy_version = policy_data.get("version", 1)
    policy.policy_description = policy_data.get("description", "")
    policy.disabled_layers = policy_data.get("disabled_layers", [])
    policy.extra_keywords = policy_data.get("extra_keywords", {})
    
    return policy

def resolve_policy_for_request(request) -> ResolvedPolicy:
    policy_name = request.headers.get("X-Heimdall-Policy", "default")
    return load_policy(policy_name)
