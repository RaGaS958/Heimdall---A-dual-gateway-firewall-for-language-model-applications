"""
GUARDIAN v2 — Cache Manager
Unified interface for all cache tiers. Called by L0 and agentic layer.
"""
from __future__ import annotations
import hashlib
from loguru import logger
from .hot_cache import HotCache
from .warm_cache import WarmCache


class CacheManager:
    """
    Unified cache interface.
    Tier 0 (hot) → exact hash — sub-ms
    Tier 1 (warm) → semantic similarity — 5-20ms
    """

    def __init__(self, settings=None):
        if settings is None:
            from config.settings import get_settings
            settings = get_settings()
        self.s = settings
        self.hot = HotCache(
            use_fake=settings.use_fake_redis,
            redis_url=settings.redis_url,
        )
        self.warm = WarmCache(
            flag_threshold=settings.warm_cache_flag_threshold,
            high_threshold=settings.warm_cache_high_threshold,
        )
        self._initialized = False
        self._pattern_hash = "unknown"
        self._schema_version = "v1"

    def initialize(self) -> None:
        """Connect caches and seed from known attack data."""
        if self._initialized:
            return
        # Compute pattern corpus hash at startup
        self._compute_pattern_hash()
        
        # Connect hot cache
        self.hot.connect()

        # Load encoder for warm cache
        self.warm.load_encoder(self.s.embedding_model)

        # Seed both caches from patterns and data files
        self._seed_caches()
        self._initialized = True
        logger.info(f"CacheManager ready — hot: {self.hot.stats}, warm size: {self.warm.size}")

    def _compute_pattern_hash(self) -> None:
        """Hash the loaded pattern corpus so the cache invalidates on pattern updates."""
        from pathlib import Path
        h = hashlib.sha256()
        pattern_path = Path(self.s.patterns_path)
        if pattern_path.exists():
            h.update(pattern_path.read_bytes())
        
        # In a real app we'd also hash BUILTIN_PATTERNS if they exist
        self._pattern_hash = h.hexdigest()[:16]

    def _get_namespace(self, policy=None) -> str:
        """Generate a versioned namespace incorporating all variables that affect verdicts."""
        policy_name = policy.policy_name if policy else "default"
        policy_version = getattr(policy, "policy_version", 1) if policy else 1
        
        warm_flag = policy.warm_cache_flag_threshold if policy else self.s.warm_cache_flag_threshold
        warm_high = getattr(policy, "warm_cache_high_threshold", self.s.warm_cache_high_threshold) if policy else self.s.warm_cache_high_threshold
        
        encoder_state = "mock" if not self.warm.is_active else self.s.embedding_model
        
        ns_str = f"{self._schema_version}:{self._pattern_hash}:{policy_name}:{policy_version}:{warm_flag}:{warm_high}:{encoder_state}"
        return hashlib.sha256(ns_str.encode()).hexdigest()[:16]

    def _seed_caches(self) -> None:
        """Load known attack data into caches."""
        import yaml
        from pathlib import Path

        # Seed hot cache from YAML exact signatures
        pattern_path = Path(self.s.patterns_path)
        if pattern_path.exists():
            data = yaml.safe_load(pattern_path.read_text())
            sigs = data.get("known_exact_signatures", [])
            # For seeding, we'll use a default namespace since these are fixed attacks.
            # But wait, seeding means they should apply across namespaces if they are ground truth?
            # Actually, `hot_cache` will need the namespace. Let's pass a generic one or None?
            # Let's seed per default namespace.
            ns = self._get_namespace()
            self.hot.seed_from_patterns(sigs, namespace=ns)

        # Seed warm cache from data file
        self.warm.seed_from_file(self.s.known_attacks_path)

    def check(self, text: str, policy=None) -> dict:
        """
        Full cache check: hot first, then warm.
        Returns result dict with 'tier', 'hit', and match metadata.
        """
        ns = self._get_namespace(policy)
        
        # Tier 0: exact hash
        hot_result = self.hot.check(text, namespace=ns)
        if hot_result:
            if hot_result.get("verdict") == "PASS":
                return {
                    "tier": 0,
                    "hit": True,
                    "is_high": False,
                    "flag": False,
                    "verdict": "PASS"
                }
            return {
                "tier": 0,
                "hit": True,
                "is_high": True,
                "similarity": 1.0,
                "verdict": "BLOCK",
                **hot_result,
            }

        # Tier 1: semantic similarity
        encoder_state = "mock" if not self.warm.is_active else self.s.embedding_model
        warm_result = self.warm.check(text, policy=policy, encoder_state=encoder_state)
        if warm_result:
            if not hasattr(self, "_recent_warm_hits"):
                self._recent_warm_hits = []
            self._recent_warm_hits.append(text)
            if len(self._recent_warm_hits) > 100:
                self._recent_warm_hits.pop(0)

            return {
                "tier": 1,
                "hit": warm_result["is_high"],   # hit only if above high threshold
                "flag": True,                     # always flag warm cache matches
                "verdict": "BLOCK",
                **warm_result,
            }

        return {"tier": -1, "hit": False, "flag": False}

    def store_attack(self, text: str, family: str, severity: int,
                     add_to_hot: bool = True, add_to_warm: bool = True, policy=None) -> None:
        """Store a confirmed attack in appropriate cache tiers."""
        ns = self._get_namespace(policy)
        metadata = {"family": family, "severity": severity, "source": "local", "verdict": "BLOCK"}
        if add_to_hot:
            self.hot.store(text, metadata, namespace=ns, ttl=86400 * 30) # 30 days for attacks
        if add_to_warm:
            encoder_state = "mock" if not self.warm.is_active else self.s.embedding_model
            self.warm.store(text, family=family, severity=severity, source="local", encoder_state=encoder_state)

    def store_pass(self, text: str, policy=None) -> None:
        """Store a PASS verdict in hot cache with short TTL."""
        ns = self._get_namespace(policy)
        metadata = {"verdict": "PASS", "source": "local"}
        self.hot.store(text, metadata, namespace=ns, ttl=300) # 5 minutes for PASS

    def stats(self) -> dict:
        return {
            "hot": self.hot.stats,
            "warm": self.warm.stats,
        }
