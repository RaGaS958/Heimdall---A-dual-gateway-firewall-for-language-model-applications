"""L0 warm cache: semantic near-duplicate lookup against known attacks.

Bug fixed here: entries were stored under encoder_state "fastembed" but checked under
the configured model name, so no entry ever matched and the tier was dead. Lookups are
now a single matrix multiply rather than a Python loop, and the store is size-capped
so confirmed-attack inserts cannot grow memory without bound. With no real encoder the
tier is off: the old hash-based mock returned high similarity for unrelated text.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

import numpy as np
from loguru import logger

from core.embeddings import embedding_service


class WarmCache:
    def __init__(self, flag_threshold: float = 0.82, high_threshold: float = 0.92, max_entries: int = 5_000):
        self.flag_threshold = flag_threshold
        self.high_threshold = high_threshold
        self.max_entries = max_entries
        self._entries: List[dict] = []
        self._matrix: Optional[np.ndarray] = None
        self._seed_path: Optional[str] = None

    def load_encoder(self, model_name: str = "") -> None:
        embedding_service.on_ready(self._seed_now)

    @property
    def is_active(self) -> bool:
        return embedding_service.is_active

    def _embed(self, text: str):
        return embedding_service.embed(text)

    def _rebuild(self) -> None:
        self._matrix = np.vstack([e["embedding"] for e in self._entries]) if self._entries else None

    def check(self, text: str, policy=None, encoder_state: str = "") -> Optional[dict]:
        if self._matrix is None or not self.is_active:
            return None
        flag_threshold = policy.warm_cache_flag_threshold if policy else self.flag_threshold
        high_threshold = policy.warm_cache_high_threshold if policy else self.high_threshold
        vector = self._embed(text)
        if vector is None:
            return None
        similarities = self._matrix @ vector
        best = int(similarities.argmax())
        score = float(similarities[best])
        if score < flag_threshold:
            return None
        entry = self._entries[best]
        return {"similarity": score, "family": entry["family"], "severity": entry["severity"],
                "is_high": score >= high_threshold, "flag": True}

    def store(self, text: str, family: str, severity: int, source: str = "local", encoder_state: str = "") -> None:
        vector = self._embed(text)
        if vector is None:
            return
        self._entries.append({"embedding": vector, "family": family, "severity": severity, "source": source})
        if len(self._entries) > self.max_entries:
            self._entries = self._entries[-self.max_entries:]
        self._rebuild()

    def seed_from_file(self, path: str) -> None:
        self._seed_path = path
        if self.is_active:
            self._seed_now()

    def _seed_now(self) -> None:
        if not self._seed_path or not Path(self._seed_path).exists():
            return
        try:
            attacks = [a for a in json.loads(Path(self._seed_path).read_text(encoding="utf-8"))
                       if isinstance(a, dict) and a.get("text")]
            matrix = embedding_service.embed_many([a["text"] for a in attacks])
            if matrix is None:
                return
            self._entries = [{"embedding": matrix[i], "family": a.get("family", "UNKNOWN"),
                              "severity": a.get("severity", 7), "source": "seed"}
                             for i, a in enumerate(attacks)]
            self._rebuild()
            logger.info(f"WarmCache seeded with {len(attacks)} entries")
        except Exception as exc:
            logger.warning(f"WarmCache seed error: {exc}")

    @property
    def size(self) -> int:
        return len(self._entries)

    @property
    def stats(self) -> dict:
        return {"size": self.size, "active": self.is_active,
                "threshold_flag": self.flag_threshold, "threshold_high": self.high_threshold}
