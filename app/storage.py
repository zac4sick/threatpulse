"""Where data.json lives: a Cloud Storage bucket in production, a local file in development.

Cloud Run instances are stateless and scale to zero, so the bucket is the source of truth.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

OBJECT = "data.json"


class Store:
    def __init__(self) -> None:
        self.bucket_name = os.environ.get("DATA_BUCKET")
        self.local = Path(os.environ.get("DATA_PATH", "/tmp/threatpulse/data.json"))
        self._bucket = None
        if self.bucket_name:
            from google.cloud import storage  # imported lazily so local dev needs no GCP libs
            self._bucket = storage.Client().bucket(self.bucket_name)

    def load(self) -> dict | None:
        if self._bucket is not None:
            blob = self._bucket.blob(OBJECT)
            return json.loads(blob.download_as_bytes()) if blob.exists() else None
        return json.loads(self.local.read_text()) if self.local.exists() else None

    def save(self, data: dict) -> None:
        raw = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
        if self._bucket is not None:
            blob = self._bucket.blob(OBJECT)
            blob.cache_control = "no-store"
            blob.upload_from_string(raw, content_type="application/json")
            # dated snapshot for history / trend research (cheap: ~100 KB per day)
            self._bucket.blob(f"history/{data['generated'][:10]}.json").upload_from_string(
                raw, content_type="application/json")
            return
        self.local.parent.mkdir(parents=True, exist_ok=True)
        self.local.write_text(raw)
