import time
import random
from enum import Enum
from dataclasses import dataclass
from collections import deque
import asyncio

class BreakerState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"

@dataclass
class CallRecord:
    timestamp: float
    success: bool
    latency_ms: float

class CircuitBreaker:
    def __init__(self, 
                 name: str, 
                 error_threshold: float = 0.5, 
                 min_requests: int = 5, 
                 window_time: float = 60.0, 
                 cooldown_time: float = 30.0, 
                 half_open_rate: float = 0.2):
        self.name = name
        self.error_threshold = error_threshold
        self.min_requests = min_requests
        self.window_time = window_time
        self.cooldown_time = cooldown_time
        self.half_open_rate = half_open_rate
        
        self.state = BreakerState.CLOSED
        self.last_state_change = time.time()
        
        self.history: deque[CallRecord] = deque()
        
        # State tracking for reporting
        self.current_error_rate = 0.0
        self.current_p95_latency = 0.0

    def _cleanup(self):
        now = time.time()
        while self.history and now - self.history[0].timestamp > self.window_time:
            self.history.popleft()

    def _update_metrics(self):
        self._cleanup()
        if not self.history:
            self.current_error_rate = 0.0
            self.current_p95_latency = 0.0
            return
            
        errors = sum(1 for r in self.history if not r.success)
        self.current_error_rate = errors / len(self.history)
        
        latencies = sorted([r.latency_ms for r in self.history])
        p95_idx = int(len(latencies) * 0.95) - 1
        if p95_idx < 0:
            p95_idx = 0
        self.current_p95_latency = latencies[p95_idx] if latencies else 0.0

    def allow_request(self) -> bool:
        """Returns True if the request should be allowed to proceed."""
        now = time.time()
        
        if self.state == BreakerState.OPEN:
            if now - self.last_state_change >= self.cooldown_time:
                self._transition(BreakerState.HALF_OPEN)
                # Fall through to HALF_OPEN logic
            else:
                return False
                
        if self.state == BreakerState.HALF_OPEN:
            # Allow a fraction of requests through
            if random.random() < self.half_open_rate:
                return True
            return False
            
        return True

    def record_result(self, success: bool, latency_ms: float):
        """Record the result of a request to update breaker state."""
        now = time.time()
        self.history.append(CallRecord(timestamp=now, success=success, latency_ms=latency_ms))
        self._update_metrics()
        
        if self.state == BreakerState.HALF_OPEN:
            if success:
                self._transition(BreakerState.CLOSED)
            else:
                self._transition(BreakerState.OPEN)
                
        elif self.state == BreakerState.CLOSED:
            if len(self.history) >= self.min_requests and self.current_error_rate >= self.error_threshold:
                self._transition(BreakerState.OPEN)

    def _transition(self, new_state: BreakerState):
        if self.state != new_state:
            self.state = new_state
            self.last_state_change = time.time()
            if new_state == BreakerState.CLOSED:
                self.history.clear() # Reset on close
                
    def get_state_dict(self):
        self._update_metrics()
        return {
            "name": self.name,
            "state": self.state.value,
            "error_rate": round(self.current_error_rate, 2),
            "p95_latency_ms": round(self.current_p95_latency, 2),
            "cooldown_remaining_s": round(max(0, self.cooldown_time - (time.time() - self.last_state_change)), 1) if self.state == BreakerState.OPEN else 0
        }
