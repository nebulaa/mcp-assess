"""Invoke policy: Safe / Unsafe / high-impact gates."""

from __future__ import annotations

from dataclasses import dataclass, field

from mcp_assess.models import AssessmentMode, ImpactClass, ToolInfo
from mcp_assess.surface.classify import CLASSIFIER_ID, is_high_impact


@dataclass
class InvokePolicy:
    mode: AssessmentMode = AssessmentMode.SAFE
    probe_high_impact: bool = False
    high_impact_extra: list[str] = field(default_factory=list)
    high_impact_except: set[str] = field(default_factory=set)
    classifier_id: str = CLASSIFIER_ID

    def tool_is_high_impact(self, tool: ToolInfo) -> bool:
        return is_high_impact(
            tool.name,
            tool.description,
            tool.input_schema,
            extra_patterns=self.high_impact_extra,
            except_names=self.high_impact_except,
        ) or tool.impact_class == ImpactClass.HIGH.value

    def may_invoke(self, tool: ToolInfo) -> tuple[bool, str | None]:
        high = self.tool_is_high_impact(tool)
        if high and not self.probe_high_impact:
            return False, "high_impact_gated"
        if tool.impact_class == ImpactClass.LOW.value or not high:
            # low-impact always ok in Safe
            if not high:
                # mutate-looking but not high-impact: Safe allows only low; Unsafe allows mutate
                if (
                    self.mode == AssessmentMode.SAFE
                    and tool.capability_class in {"mutate", "egress", "admin", "exec"}
                ):
                    # If classifier marked low but capability is mutate, treat as unsafe-only
                    # unless truly low-impact name class
                    if tool.capability_class != "read" and tool.capability_class != "other":
                        # Soft: Safe still allows capability_class mutate only if impact is low
                        # Spec: Safe = low-impact Invoke only. capability mutate + low impact
                        # means non-high-impact mutate → Unsafe only.
                        if tool.capability_class in {"mutate", "egress", "exec", "admin"}:
                            if self.mode == AssessmentMode.SAFE:
                                return False, "unsafe_required"
                return True, None
        if high and self.probe_high_impact:
            return True, None
        if self.mode == AssessmentMode.UNSAFE:
            return True, None
        return False, "unsafe_required"

    def to_dict(self, *, spawned_stdio: bool) -> dict:
        return {
            "mode": self.mode.value,
            "high_impact_probes": self.probe_high_impact,
            "classifier_id": self.classifier_id,
            "high_impact_extra": list(self.high_impact_extra),
            "high_impact_except": sorted(self.high_impact_except),
            "spawned_stdio": spawned_stdio,
        }


def minimal_inert_args(schema: dict | None) -> dict:
    """Build minimal inert arguments from JSON schema (no secrets, no real paths)."""
    if not schema or not isinstance(schema, dict):
        return {}
    props = schema.get("properties") or {}
    required = set(schema.get("required") or [])
    args: dict = {}
    for name in required:
        prop = props.get(name) if isinstance(props, dict) else None
        args[name] = _inert_for_prop(prop)
    return args


def _inert_for_prop(prop: dict | None):
    if not isinstance(prop, dict):
        return ""
    t = prop.get("type")
    if t == "string" or t is None:
        return ""
    if t == "integer" or t == "number":
        return 0
    if t == "boolean":
        return False
    if t == "array":
        return []
    if t == "object":
        return {}
    if isinstance(t, list):
        # nullable unions — pick first non-null
        for opt in t:
            if opt != "null":
                return _inert_for_prop({"type": opt})
    return ""
