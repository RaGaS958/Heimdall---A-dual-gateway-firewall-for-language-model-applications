"""Shared sentence-embedding service.

L0 (warm cache), L3 and the trajectory monitor all need the same vector for the same
text. One encoder and one LRU cache replace three separate embedding passes per
request. The model loads on a background thread so the API is ready immediately and
a cold start never blocks; until it finishes L3 runs on the bundled lexical model.
"""
from __future__ import annotations

import hashlib
import threading
from collections import OrderedDict
from typing import Callable, List, Optional

import numpy as np
from loguru import logger


class EmbeddingService:
    def __init__(self, cache_size: int = 2_048):
        self._model = None
        self.model_name: Optional[str] = None
        self.state = "disabled"  # disabled | warming | ready | unavailable
        self._lock = threading.Lock()
        self._cache: "OrderedDict[str, np.ndarray]" = OrderedDict()
        self._cache_size = cache_size
        self._on_ready: List[Callable[[], None]] = []

    @property
    def is_active(self) -> bool:
        return self.state == "ready"

    def on_ready(self, callback: Callable[[], None]) -> None:
        if self.is_active:
            callback()
        else:
            self._on_ready.append(callback)

    def start(self, model_name: str, enabled: bool = True, background: bool = True) -> None:
        if not enabled:
            self.state = "disabled"
            return
        if self.state in ("warming", "ready"):
            return
        self.model_name = model_name
        self.state = "warming"
        if background:
            threading.Thread(target=self._load, name="embedding-loader", daemon=True).start()
        else:
            self._load()

    def _load(self) -> None:
        try:
            from fastembed import TextEmbedding
            self._model = TextEmbedding(self.model_name)
            self.state = "ready"
            logger.info(f"Embedding model ready: {self.model_name}")
        except Exception as exc:
            self.state = "unavailable"
            logger.warning(f"Embedding model unavailable, semantic layers stay off: {exc}")
            return
        for callback in self._on_ready:
            try:
                callback()
            except Exception as exc:
                logger.error(f"Embedding on-ready hook failed: {exc}")

    def embed(self, text: str) -> Optional[np.ndarray]:
        """Unit-length vector for the text, or None when no model is loaded."""
        if not self.is_active:
            return None
        key = hashlib.sha256(text.encode("utf-8", "ignore")).hexdigest()
        with self._lock:
            hit = self._cache.get(key)
            if hit is not None:
                self._cache.move_to_end(key)
                return hit
            vector = np.asarray(next(iter(self._model.embed([text]))), dtype=np.float32)
            vector = vector / (np.linalg.norm(vector) + 1e-9)
            self._cache[key] = vector
            while len(self._cache) > self._cache_size:
                self._cache.popitem(last=False)
            return vector

    def embed_many(self, texts: List[str]) -> Optional[np.ndarray]:
        if not self.is_active or not texts:
            return None
        with self._lock:
            matrix = np.asarray(list(self._model.embed(texts)), dtype=np.float32)
        return matrix / (np.linalg.norm(matrix, axis=1, keepdims=True) + 1e-9)


embedding_service = EmbeddingService()
