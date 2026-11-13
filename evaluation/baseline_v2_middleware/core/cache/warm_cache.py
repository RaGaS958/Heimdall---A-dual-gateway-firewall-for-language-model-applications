"""GUARDIAN v2 — Warm Cache (Tier 1): Cosine similarity via sentence-transformers."""
from __future__ import annotations
import hashlib, json
from pathlib import Path
from loguru import logger

class WarmCache:
    def __init__(self, flag_threshold: float = 0.82, high_threshold: float = 0.92):
        self.flag_threshold = flag_threshold
        self.high_threshold = high_threshold
        self._encoder = None
        self._entries: list[dict] = []   # {embedding, family, severity}
        try:
            import numpy as np
            self._np = np
        except ImportError:
            self._np = None

    def load_encoder(self, model_name: str) -> None:
        try:
            from fastembed import TextEmbedding
            self._encoder = TextEmbedding("BAAI/bge-small-en-v1.5")
            logger.info(f"WarmCache encoder loaded: fastembed")
        except Exception as e:
            logger.warning(f"WarmCache real encoder unavailable ({e}), using mock")
            self._encoder = _MockEncoder()

    @property
    def is_active(self) -> bool:
        return self._encoder is not None and not isinstance(self._encoder, _MockEncoder)

    def _embed(self, text: str):
        if self._encoder is None:
            self._encoder = _MockEncoder()
        return list(self._encoder.embed([text]))[0]

    def check(self, text: str, policy=None, encoder_state: str = "mock") -> dict | None:
        if not self._entries or self._np is None:
            return None
            
        flag_threshold = policy.warm_cache_flag_threshold if policy else self.flag_threshold
        high_threshold = policy.warm_cache_high_threshold if (policy and hasattr(policy, "warm_cache_high_threshold")) else self.high_threshold
        
        vec = self._embed(text)
        best_sim, best_entry = 0.0, None
        for entry in self._entries:
            if entry.get("encoder_state", "mock") != encoder_state:
                continue
            sim = float(self._np.dot(vec, entry["embedding"]) /
                        (self._np.linalg.norm(vec) * self._np.linalg.norm(entry["embedding"]) + 1e-9))
            if sim > best_sim:
                best_sim, best_entry = sim, entry
        if best_sim >= flag_threshold and best_entry:
            return {"similarity": best_sim, "family": best_entry["family"],
                    "severity": best_entry["severity"],
                    "is_high": best_sim >= high_threshold, "flag": True}
        return None

    def store(self, text: str, family: str, severity: int, source: str = "local", encoder_state: str = "mock") -> None:
        emb = self._embed(text)
        self._entries.append({"embedding": emb, "family": family,
                               "severity": severity, "source": source, "encoder_state": encoder_state})

    def seed_from_file(self, path: str) -> None:
        p = Path(path)
        if not p.exists():
            return
        try:
            attacks = json.loads(p.read_text())
            encoder_state = "mock" if not self.is_active else "fastembed"
            for a in attacks:
                if isinstance(a, dict) and "text" in a:
                    self.store(a["text"], a.get("family","UNKNOWN"), a.get("severity", 7), encoder_state=encoder_state)
            logger.info(f"WarmCache seeded with {len(attacks)} entries from {path}")
        except Exception as e:
            logger.warning(f"WarmCache seed error: {e}")

    @property
    def size(self) -> int:
        return len(self._entries)

    @property
    def stats(self) -> dict:
        return {"size": self.size, "threshold_flag": self.flag_threshold,
                "threshold_high": self.high_threshold}


class _MockEncoder:
    """SHA-256 based mock encoder — works for tests without HuggingFace."""
    def embed(self, texts: list[str]):
        import hashlib
        try:
            import numpy as np
        except ImportError:
            yield from [[0.0]*64 for _ in texts]
            return
        ATTACK_KEYWORDS = ["ignore", "override", "system", "prompt", "jailbreak",
                           "pretend", "forget", "instructions", "bypass", "reveal",
                           "extract", "unlimited", "unrestricted", "disregard"]
        for text in texts:
            h = hashlib.sha256(text.encode()).digest()
            vec = np.frombuffer(h, dtype=np.uint8).astype(np.float32)
            vec = vec / (np.linalg.norm(vec) + 1e-9)
            low = text.lower()
            bias = sum(0.05 for kw in ATTACK_KEYWORDS if kw in low)
            vec = vec + bias
            vec = vec / (np.linalg.norm(vec) + 1e-9)
            yield vec
