"""L3b: hashed character n-gram logistic regression.

Dependency-free, sub-millisecond, and needs no model download, so L3 still has a
learned signal on a cold start or air-gapped host. Replaces the old fallback that
counted keyword substrings. Train with evaluation/train_lexical.py on the
development corpus only; the Phase 12 held-out set is never used for fitting.
"""
from __future__ import annotations

import base64
import json
import math
import re
import zlib
from pathlib import Path
from typing import Iterable, Optional

import numpy as np

_WS = re.compile(r"\s+")


def featurize_v1(text: str, dim: int, nmin: int = 3, nmax: int = 5) -> np.ndarray:
    """The lex-1 feature function (CRC32 per n-gram). Kept so an old model file still loads."""
    normalized = " " + _WS.sub(" ", text.lower()).strip() + " "
    counts: dict[int, float] = {}
    encoded = normalized.encode("utf-8", "ignore")[:6000]
    for n in range(nmin, nmax + 1):
        for i in range(len(encoded) - n + 1):
            index = zlib.crc32(encoded[i:i + n]) % dim
            counts[index] = counts.get(index, 0.0) + 1.0
    vector = np.zeros(dim, dtype=np.float32)
    for index, value in counts.items():
        vector[index] = 1.0 + math.log(value)
    norm = np.linalg.norm(vector)
    return vector / norm if norm else vector


_MULT = np.uint64(1099511628211)
_SEEDS = {n: np.uint64(1469598103934665603 + 7919 * n) for n in range(1, 9)}
MAX_BYTES = 12000


def featurize(text: str, dim: int, nmin: int = 3, nmax: int = 5) -> np.ndarray:
    """Hashed character n-grams, vectorised: about 0.2 ms for a 6 KB prompt instead of 8 ms.

    Long prompts keep their head and tail, because injected instructions sit at either end
    of a long filler block far more often than in the middle.
    """
    normalized = (" " + _WS.sub(" ", text.lower()).strip() + " ").encode("utf-8", "ignore")
    if len(normalized) > MAX_BYTES:
        normalized = normalized[:MAX_BYTES // 2] + b" " + normalized[-MAX_BYTES // 2:]
    data = np.frombuffer(normalized, dtype=np.uint8).astype(np.uint64)
    vector = np.zeros(dim, dtype=np.float32)
    with np.errstate(over="ignore"):
        for n in range(nmin, nmax + 1):
            if len(data) < n:
                continue
            acc = np.full(len(data) - n + 1, _SEEDS[n], dtype=np.uint64)
            for k in range(n):
                acc = (acc ^ data[k:len(data) - n + 1 + k]) * _MULT
            acc ^= acc >> np.uint64(29)
            vector += np.bincount((acc % np.uint64(dim)).astype(np.int64), minlength=dim).astype(np.float32)
    seen = vector > 0
    vector[seen] = 1.0 + np.log(vector[seen])
    norm = float(np.linalg.norm(vector))
    return vector / norm if norm else vector


class LexicalClassifier:
    def __init__(self):
        self.weights: Optional[np.ndarray] = None
        self.intercept = 0.0
        self.dim = 0
        self.info: dict = {}
        self._featurize = featurize

    @property
    def is_active(self) -> bool:
        return self.weights is not None

    def load(self, path: str) -> bool:
        file = Path(path)
        if not file.exists():
            return False
        data = json.loads(file.read_text(encoding="utf-8"))
        raw = zlib.decompress(base64.b64decode(data["weights_b64"]))
        self.weights = np.frombuffer(raw, dtype=np.float16).astype(np.float32)
        self.intercept = float(data["intercept"])
        self.dim = int(data["dim"])
        self.info = {k: v for k, v in data.items() if k != "weights_b64"}
        self._featurize = featurize_v1 if data.get("version") == "lex-1" else featurize
        return True

    def score(self, text: str) -> float:
        if not self.is_active or not text.strip():
            return 0.0
        z = float(self.weights @ self._featurize(text, self.dim)) + self.intercept
        return 1.0 / (1.0 + math.exp(-z))

    def score_views(self, texts: Iterable[str]) -> float:
        return max((self.score(t) for t in texts), default=0.0)
