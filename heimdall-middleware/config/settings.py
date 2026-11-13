"""HEIMDALL runtime configuration.

Security-relevant rules enforced here:
  * No shared secret has a usable default. In development a random key is
    generated per process; in production a missing or placeholder secret stops
    the service from starting (fail closed, never fail open).
  * Every provider model ID is configuration, because hosted models are retired
    on the vendor's schedule (see knowledge-base/06-operations/operations.md, "Model lifecycle").
"""
from __future__ import annotations

import secrets
from functools import lru_cache
from typing import List, Literal

from pydantic import field_validator, ConfigDict, Field, model_validator
from pydantic_settings import BaseSettings

_PLACEHOLDER_MARKERS = ("your_", "change-me", "changeme", "guardian-admin-local-dev-only",
                        "heimdall-internal-dev-key", "replace-me")


def is_placeholder(value: str) -> bool:
    if not value:
        return True
    low = value.lower()
    return any(marker in low for marker in _PLACEHOLDER_MARKERS)


class Settings(BaseSettings):
    model_config = ConfigDict(env_file=".env", extra="ignore")

    # Runtime mode: development | test | production
    heimdall_env: str = "development"

    # LLM API keys
    gemini_api_key: str = ""
    groq_api_key: str = ""
    mistral_api_key: str = ""

    # Hosted model IDs. Defaults verified against vendor docs on 2026-11-09:
    # llama-3.1-8b-instant was shut down 2026-08-16 and gemini-2.0-flash-exp
    # is retired, which silently disabled the arbiter in earlier builds.
    groq_model: str = "openai/gpt-oss-20b"
    gemini_model: str = "gemini-3.5-flash"
    mistral_model: str = "mistral-small-latest"

    # Multi-LLM backend
    multi_llm_backend_url: str = "http://localhost:8001"

    # Shared secrets: empty means "generate for this process" outside production.
    internal_auth_key: str = ""
    admin_key: str = ""
    session_signing_key: str = ""

    # Server
    port: int = 8000
    frontend_urls: str = Field(default="http://localhost:5173,http://127.0.0.1:5173",
                               validation_alias="FRONTEND_URL")
    trusted_proxy_hops: int = 0
    max_body_bytes: int = 128_000

    # Rate limits, requests per minute per client
    rate_limit_chat: int = 30
    rate_limit_scan: int = 60
    rate_limit_session: int = 30
    rate_limit_admin: int = 60
    rate_limit_default: int = 300

    # Sessions
    max_sessions: int = 5_000
    session_idle_ttl: int = 3_600
    stream_token_ttl: int = 900
    session_block_strikes: int = 3
    session_block_window: int = 600
    session_block_ttl: int = 300

    # Honeypot: answers locked sessions with static decoys. Off by default so a
    # false positive can never turn into fabricated output for a real user.
    honeypot_enabled: bool = False

    # Research-only request fields (skip_layers, custom system prompt, ...).
    # Needs this flag AND a valid admin key on the request.
    research_mode: bool = False

    # Cache
    use_fake_redis: bool = True
    redis_url: str = "redis://localhost:6379"
    warm_cache_flag_threshold: float = 0.82
    warm_cache_high_threshold: float = 0.92
    warm_cache_max_entries: int = 5_000

    # ML / embeddings
    embeddings_enabled: bool = True
    embedding_model: str = "BAAI/bge-small-en-v1.5"
    ml_classifier_threshold: float = 0.70
    lexical_classifier_threshold: float = 0.80
    # At or above this score the lexical model is a strong signal by itself (severity 7): the arbiter
    # decides, and the request is blocked if the arbiter is unreachable. Calibrated by train_lexical.py
    # so that no benign out-of-fold example reaches it. Set to 0 to keep the model advisory only.
    lexical_block_threshold: float = 0.95
    intent_similarity_threshold: float = 0.75

    # Agentic escalation
    agentic_trigger_flag_count: int = 2
    agentic_trigger_severity: int = 7
    # Share of soft (below-threshold) flags reviewed by the arbiter. Selection
    # hashes the canonical text, so a given prompt always gets the same route.
    agentic_soft_flag_rate: float = 1.0
    # The arbiter's output budget. Reasoning models (gpt-oss on Groq) spend output tokens thinking
    # before they answer; at 320 about one call in six ran out before finishing its JSON.
    agentic_max_tokens: int = 1024
    # A security verdict should not depend on sampling luck.
    agentic_temperature: float = 0.0
    # Sent only to models that accept it (Groq gpt-oss). low = few reasoning tokens.
    agentic_reasoning_effort: str = "low"
    # Human review. "review": a person decides (the request waits; nothing is answered meanwhile).
    # When the arbiter fails (unreachable or an unreadable reply) on a request that carries flags:
    #   review  -> hold for a reviewer          legacy -> block hard signals, forward soft ones spotlighted
    review_on_arbiter_failure: str = "review"
    # When the arbiter clears a request the fixed layers would block on their own (a hard signal):
    #   review  -> hold for a reviewer          block -> block          allow -> accept the arbiter (pre-15 behaviour)
    arbiter_conflict_action: str = "review"
    # strip: remove active markup everywhere (safe for clients that render raw HTML).
    # keep: leave it inside code blocks, for markdown or plain-text clients; code answers stay intact.
    g2_code_blocks: Literal["strip", "keep"] = "strip"

    # Security
    system_prompt_canary: str = Field(default_factory=lambda: "HMD-CANARY-" + secrets.token_hex(6))
    leakage_similarity_threshold: float = 0.45
    regex_timeout_seconds: float = 0.05

    # Data paths
    patterns_path: str = "patterns/injection_patterns.yaml"
    known_attacks_path: str = "data/known_attacks.json"
    audit_log_path: str = "data/admin_audit.jsonl"
    # Runtime files that must survive a container being recreated. docker-compose.yml points all
    # four at a mounted volume; the defaults keep a plain checkout working unchanged.
    review_queue_path: str = "data/review_queue.json"
    reviewer_labels_path: str = "data/reviewer_labels.jsonl"
    honeypot_log_path: str = "data/honeypot_logs.jsonl"
    lexical_model_path: str = "data/lexical_l3.json"

    @field_validator("redis_url", mode="before")
    @classmethod
    def _clean_redis_url(cls, value):
        # Values pasted into a hosting console often carry spaces or quotes.
        return value.strip().strip("'\"").strip() if isinstance(value, str) else value

    @model_validator(mode="after")
    def _resolve_secrets(self) -> "Settings":
        env = self.heimdall_env.lower()
        for name in ("internal_auth_key", "admin_key", "session_signing_key"):
            value = getattr(self, name)
            if is_placeholder(value):
                if env == "production":
                    raise ValueError(
                        f"{name.upper()} must be set to a strong random value in production "
                        f"(for example: python -c 'import secrets;print(secrets.token_urlsafe(48))')"
                    )
                setattr(self, name, secrets.token_urlsafe(32))
            elif env == "production" and len(value) < 24:
                raise ValueError(f"{name.upper()} must be at least 24 characters in production")
        if env == "production" and self.research_mode:
            raise ValueError("RESEARCH_MODE cannot be enabled in production")
        return self

    @property
    def is_production(self) -> bool:
        return self.heimdall_env.lower() == "production"

    @property
    def allowed_origins(self) -> List[str]:
        return [o.strip().rstrip("/") for o in self.frontend_urls.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
