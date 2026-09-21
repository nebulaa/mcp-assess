"""Pin store: definition hashes under ~/.mcp-assess/pins/."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mcp_assess.discovery.target_id import pin_key as make_pin_key
from mcp_assess.models import EnumeratedSurface, PromptInfo, ResourceInfo, ToolInfo


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def tool_definition_hash(tool: ToolInfo) -> str:
    return sha256_hex(
        canonical_json(
            {
                "name": tool.name,
                "description": tool.description,
                "inputSchema": tool.input_schema,
            }
        )
    )


def prompt_definition_hash(prompt: PromptInfo) -> str:
    return sha256_hex(
        canonical_json(
            {
                "name": prompt.name,
                "description": prompt.description,
                "arguments": prompt.arguments,
            }
        )
    )


def resource_definition_hash(resource: ResourceInfo) -> str:
    return sha256_hex(
        canonical_json(
            {
                "uri": resource.uri,
                "name": resource.name,
                "description": resource.description,
                "mimeType": resource.mime_type,
            }
        )
    )


def surface_items(surface: EnumeratedSurface) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    for t in surface.tools:
        items.append(
            {"kind": "tool", "name": t.name, "definition_hash": tool_definition_hash(t)}
        )
    for p in surface.prompts:
        items.append(
            {
                "kind": "prompt",
                "name": p.name,
                "definition_hash": prompt_definition_hash(p),
            }
        )
    for r in surface.resources:
        items.append(
            {
                "kind": "resource",
                "name": r.uri,
                "definition_hash": resource_definition_hash(r),
            }
        )
    return items


def aggregate_surface_hash(items: list[dict[str, str]]) -> str:
    lines = sorted(f"{i['kind']}:{i['name']}:{i['definition_hash']}" for i in items)
    return sha256_hex("\n".join(lines))


class PinStore:
    def __init__(self, root: Path | None = None) -> None:
        self.root = Path(root or (Path.home() / ".mcp-assess" / "pins")).expanduser()
        self.index_path = self.root / "index.json"

    def ensure(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        if not self.index_path.exists():
            self.index_path.write_text(
                json.dumps({"schema_version": 1, "entries": {}}, indent=2)
                + "\n",
                encoding="utf-8",
            )

    def _read_index(self) -> dict[str, Any]:
        self.ensure()
        try:
            return json.loads(self.index_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {"schema_version": 1, "entries": {}}

    def _write_index(self, index: dict[str, Any]) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        self.index_path.write_text(
            json.dumps(index, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    def list_keys(self) -> list[str]:
        return sorted((self._read_index().get("entries") or {}).keys())

    def get(self, pin_key: str) -> dict[str, Any] | None:
        index = self._read_index()
        entry = (index.get("entries") or {}).get(pin_key)
        if not entry:
            return None
        path = self.root / entry["file"]
        if not path.is_file():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def delete(self, pin_key: str) -> bool:
        index = self._read_index()
        entries = index.setdefault("entries", {})
        entry = entries.pop(pin_key, None)
        if not entry:
            return False
        path = self.root / entry["file"]
        if path.is_file():
            path.unlink()
        self._write_index(index)
        return True

    def approve(
        self,
        *,
        target_id: str,
        host_config_path: str | None,
        surface: EnumeratedSurface,
        assessment_id: str | None = None,
    ) -> dict[str, Any]:
        key = make_pin_key(target_id, host_config_path)
        items = surface_items(surface)
        body = {
            "schema_version": 1,
            "pin_key": key,
            "target_id": target_id,
            "host_config_path": host_config_path,
            "approved_at": datetime.now(timezone.utc).isoformat(),
            "surface_hash": aggregate_surface_hash(items),
            "items": items,
        }
        filename = f"{sha256_hex(key)}.json"
        self.ensure()
        (self.root / filename).write_text(
            json.dumps(body, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        index = self._read_index()
        index.setdefault("entries", {})[key] = {
            "file": filename,
            "approved_at": body["approved_at"],
            "assessment_id": assessment_id,
        }
        self._write_index(index)
        return body

    def compare(
        self,
        *,
        target_id: str,
        host_config_path: str | None,
        surface: EnumeratedSurface,
    ) -> dict[str, Any]:
        key = make_pin_key(target_id, host_config_path)
        pinned = self.get(key)
        current_items = surface_items(surface)
        current_hash = aggregate_surface_hash(current_items)
        if pinned is None:
            return {
                "pin_key": key,
                "present": False,
                "drift": False,
                "changes": [],
                "current_surface_hash": current_hash,
            }

        old_map = {
            (i["kind"], i["name"]): i["definition_hash"]
            for i in pinned.get("items") or []
        }
        new_map = {
            (i["kind"], i["name"]): i["definition_hash"] for i in current_items
        }
        changes: list[dict[str, Any]] = []
        for k, new_h in new_map.items():
            if k not in old_map:
                changes.append(
                    {
                        "kind": k[0],
                        "name": k[1],
                        "change": "added",
                        "new_hash": new_h,
                    }
                )
            elif old_map[k] != new_h:
                changes.append(
                    {
                        "kind": k[0],
                        "name": k[1],
                        "change": "modified",
                        "old_hash": old_map[k],
                        "new_hash": new_h,
                    }
                )
        for k, old_h in old_map.items():
            if k not in new_map:
                changes.append(
                    {
                        "kind": k[0],
                        "name": k[1],
                        "change": "removed",
                        "old_hash": old_h,
                    }
                )
        return {
            "pin_key": key,
            "present": True,
            "drift": bool(changes) or pinned.get("surface_hash") != current_hash,
            "changes": changes,
            "old_surface_hash": pinned.get("surface_hash"),
            "current_surface_hash": current_hash,
        }
