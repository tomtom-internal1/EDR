from __future__ import annotations

from collections import deque

from models import CollectorStats, Event


class TrainingCollector:
    """Deterministic telemetry collector used only by the lab."""

    def __init__(self, capacity: int = 1000):
        self.capacity = max(1, capacity)
        self.queue: deque[Event] = deque(maxlen=self.capacity)
        self.stats = CollectorStats()

    def submit(self, event: Event) -> bool:
        self.stats.received += 1
        if len(self.queue) >= self.capacity:
            self.stats.dropped += 1
            return False
        self.queue.append(event)
        return True

    def drain(self) -> list[Event]:
        events = list(self.queue)
        self.queue.clear()
        return events
