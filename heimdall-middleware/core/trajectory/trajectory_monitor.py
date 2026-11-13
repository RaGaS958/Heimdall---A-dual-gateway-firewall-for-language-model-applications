"""GUARDIAN v2 — Trajectory Monitor."""
from __future__ import annotations
import time
import math
from collections import OrderedDict, deque
from typing import Optional

from core.models import RequestContext, Flag, FlagSource, AttackFamily
from core.cache.warm_cache import WarmCache
from core.gateway1.l4_intent_engine import IntentEngine

class SessionTrajectory:
    def __init__(self, max_turns: int = 10):
        self.max_turns = max_turns
        # stores dict with turn_index, vector, timestamp, is_fallback, attack_sim
        self.history = deque(maxlen=max_turns)
        
class TrajectoryMonitor:
    def __init__(
        self, 
        cache: WarmCache, 
        intent: IntentEngine, 
        max_turns: int = 10, 
        turn_drift_threshold: float = 3.0, 
        cumulative_drift_threshold: float = 0.65
    ):
        self.cache = cache
        self.intent = intent
        self.max_turns = max_turns
        self.sessions: "OrderedDict[str, SessionTrajectory]" = OrderedDict()
        self.max_sessions = 5_000
        self.turn_drift_threshold = turn_drift_threshold
        self.cumulative_drift_threshold = cumulative_drift_threshold
        
        try:
            import numpy as np
            self.np = np
        except ImportError:
            self.np = None

    def _cosine_distance(self, v1, v2) -> float:
        if self.np:
            norm = self.np.linalg.norm(v1) * self.np.linalg.norm(v2)
            if norm == 0: return 0.0
            return 1.0 - float(self.np.dot(v1, v2) / norm)
        else:
            dot = sum(a * b for a, b in zip(v1, v2))
            mag1 = math.sqrt(sum(a * a for a in v1))
            mag2 = math.sqrt(sum(a * a for a in v2))
            if mag1 * mag2 == 0: return 0.0 if v1 == v2 else 1.0
            return 1.0 - (dot / (mag1 * mag2))

    def _cosine_similarity(self, v1, v2) -> float:
        if self.np:
            norm = self.np.linalg.norm(v1) * self.np.linalg.norm(v2)
            if norm == 0: return 0.0
            return float(self.np.dot(v1, v2) / norm)
        else:
            dot = sum(a * b for a, b in zip(v1, v2))
            mag1 = math.sqrt(sum(a * a for a in v1))
            mag2 = math.sqrt(sum(a * a for a in v2))
            if mag1 * mag2 == 0: return 1.0 if v1 == v2 else 0.0
            return dot / (mag1 * mag2)

    def get_trajectory_data(self, session_id: str) -> list[dict]:
        """For GET /trajectory/{session_id} debug endpoint."""
        if session_id not in self.sessions:
            return []
        return list(self.sessions[session_id].history)

    def run(self, ctx: RequestContext) -> None:
        if not ctx.session:
            return
            
        sid = ctx.session.session_id
        if sid not in self.sessions:
            self.sessions[sid] = SessionTrajectory(max_turns=self.max_turns)
            while len(self.sessions) > self.max_sessions:
                self.sessions.popitem(last=False)
        self.sessions.move_to_end(sid)

        traj = self.sessions[sid]
        text = ctx.canonical_input or ctx.raw_input
        
        is_fallback = not self.cache.is_active
        if not is_fallback:
            vector = self.cache._embed(text)
            if vector is None:
                return
        else:
            auth, urg, evas = self.intent.score_axes(text)
            vector = [auth, urg, evas]

        turn_index = ctx.session.turn_count
        timestamp = time.time()
        
        current_entry = {
            "turn_index": turn_index,
            "vector": vector if not self.np else vector.tolist() if hasattr(vector, "tolist") else vector,
            "timestamp": timestamp,
            "is_fallback": is_fallback,
            "turn_drift": 0.0,
            "cumulative_drift": 0.0,
            "attack_sim": 0.0,
            "preview_chars": len(text),
        }
        
        attack_sim = 0.0
        if is_fallback:
            attack_sim = self._cosine_similarity(vector, [1.0, 1.0, 1.0])
        elif self.cache._matrix is not None:
            attack_sim = float((self.cache._matrix @ vector).max())

        current_entry["attack_sim"] = attack_sim
        
        if len(traj.history) > 0:
            last_entry = traj.history[-1]
            first_entry = traj.history[0]
            
            if last_entry["is_fallback"] == is_fallback:
                distance = self._cosine_distance(vector, last_entry["vector"])
                current_entry["turn_drift"] = distance
                
                if len(traj.history) >= 2:
                    past_dists = []
                    for i in range(1, len(traj.history)):
                        if traj.history[i]["is_fallback"] == is_fallback and traj.history[i-1]["is_fallback"] == is_fallback:
                            d = traj.history[i].get("turn_drift", 0.0)
                            past_dists.append(d)
                    
                    if past_dists:
                        avg_dist = sum(past_dists) / len(past_dists)
                        if avg_dist > 0.05 and distance > self.turn_drift_threshold * avg_dist:
                            ctx.add_flag(Flag(
                                source=FlagSource.TRAJECTORY,
                                severity=7,
                                confidence=0.8,
                                attack_families=[AttackFamily.MULTI_TURN],
                                evidence=f"turn-to-turn drift spike={distance:.2f}, avg={avg_dist:.2f} over {len(past_dists)} turns (mode={'axis_fallback' if is_fallback else 'real'})"
                            ))

                cum_distance = self._cosine_distance(vector, first_entry["vector"])
                current_entry["cumulative_drift"] = cum_distance
                
                threshold = self.cumulative_drift_threshold if not is_fallback else 0.35
                if cum_distance > threshold:
                    ctx.add_flag(Flag(
                        source=FlagSource.TRAJECTORY,
                        severity=6,
                        confidence=0.7,
                        attack_families=[AttackFamily.MULTI_TURN],
                        evidence=f"cumulative_drift={cum_distance:.2f} over {len(traj.history)} turns, threshold={threshold} (mode={'axis_fallback' if is_fallback else 'real'})"
                    ))
                    
                if len(traj.history) >= 2 and attack_sim > 0.0:
                    past_1 = last_entry.get("attack_sim", 0.0)
                    past_2 = traj.history[-2].get("attack_sim", 0.0) if len(traj.history) >= 2 else 0.0
                    
                    if attack_sim > past_1 and past_1 > past_2 and past_2 > 0:
                        min_sim = 0.4 if not is_fallback else 0.6
                        if attack_sim > min_sim:
                            ctx.add_flag(Flag(
                                source=FlagSource.TRAJECTORY,
                                severity=7,
                                confidence=0.8,
                                attack_families=[AttackFamily.MULTI_TURN],
                                evidence=f"attack-region proximity steadily increasing: {past_2:.2f} -> {past_1:.2f} -> {attack_sim:.2f} over 3 turns (mode={'axis_fallback' if is_fallback else 'real'})"
                            ))

        traj.history.append(current_entry)
