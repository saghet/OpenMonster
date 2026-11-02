"""
Structured Real-Time Event Emitter.
Transmits JSON Lines over stdout for the parent Tauri/Rust orchestrator.
"""

import json
import sys
import time
from typing import Any, Dict, Optional


class EventEmitter:
    def __init__(self, scan_id: str, asset_id: str):
        self.scan_id = scan_id
        self.asset_id = asset_id

    def _emit(self, event_type: str, data: Dict[str, Any]) -> None:
        payload = {
            "type": event_type,
            "scan_id": self.scan_id,
            "asset_id": self.asset_id,
            "timestamp": time.time(),
            "data": data,
        }
        # Print JSON on its own single line and flush immediately
        sys.stdout.write(json.dumps(payload) + "\n")
        sys.stdout.flush()

    def log(self, message: str, level: str = "INFO") -> None:
        self._emit("log", {"message": message, "level": level})

    def progress(self, percent: float, current_task: str) -> None:
        self._emit("progress", {"percent": percent, "current_task": current_task})

    def finding(self, finding_data: Dict[str, Any]) -> None:
        self._emit("finding", finding_data)

    def completed(self, summary: Dict[str, Any]) -> None:
        self._emit("completed", summary)

    def error(self, message: str) -> None:
        self._emit("error", {"message": message})
