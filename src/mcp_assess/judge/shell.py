"""Judge shell-out contract."""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcp_assess.judge.rubrics import RUBRICS


@dataclass
class JudgeResult:
    verdict: str  # clean|suspicious|poisoned|error
    score: float | int | None = None
    rationale: str = ""
    severity_hint: str | None = None
    raw_stdout: str = ""
    error: str | None = None


_JSON_OBJECT = re.compile(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", re.DOTALL)


def last_json_object(text: str) -> dict[str, Any] | None:
    """Parse the last JSON object from stdout (allows chatter)."""
    text = text.strip()
    if not text:
        return None
    # Try whole text first
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except json.JSONDecodeError:
        pass
    # Scan for JSON objects; take the last that parses
    candidates = list(_JSON_OBJECT.finditer(text))
    # Also try from each '{'
    last: dict[str, Any] | None = None
    for i, ch in enumerate(text):
        if ch != "{":
            continue
        for j in range(len(text), i, -1):
            chunk = text[i:j]
            try:
                obj = json.loads(chunk)
                if isinstance(obj, dict):
                    last = obj
                    break
            except json.JSONDecodeError:
                continue
    return last


class Judge:
    def __init__(
        self,
        command_template: str | None,
        *,
        timeout_sec: float = 60.0,
        fail_fast: bool = False,
        verbose: bool = False,
    ) -> None:
        self.command_template = command_template
        self.timeout_sec = timeout_sec
        self.fail_fast = fail_fast
        self.verbose = verbose

    @property
    def configured(self) -> bool:
        return bool(self.command_template and self.command_template.strip())

    def score(
        self,
        *,
        check_id: str,
        target_id: str,
        subject_kind: str,
        subject: dict[str, Any],
        rubric: str | None = None,
    ) -> JudgeResult:
        if not self.configured:
            return JudgeResult(
                verdict="error",
                rationale="judge_unset",
                error="judge_unset",
            )

        request = {
            "schema_version": 1,
            "check_id": check_id,
            "target_id": target_id,
            "subject_kind": subject_kind,
            "subject": subject,
            "rubric": rubric or RUBRICS.get(check_id, ""),
        }
        request_json = json.dumps(request, ensure_ascii=False)
        timeout_ms = int(self.timeout_sec * 1000)

        prompt_file: Path | None = None
        try:
            cmd = self.command_template or ""
            if "{prompt_file}" in cmd:
                fd, path = tempfile.mkstemp(prefix="mcp-assess-judge-", suffix=".json")
                os.close(fd)
                prompt_file = Path(path)
                prompt_file.write_text(request_json, encoding="utf-8")
            cmd = (
                cmd.replace("{prompt_file}", str(prompt_file) if prompt_file else "")
                .replace("{timeout_ms}", str(timeout_ms))
                .replace("{check_id}", check_id)
                .replace("{subject_kind}", subject_kind)
            )

            try:
                proc = subprocess.run(
                    cmd,
                    shell=True,
                    input=request_json,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_sec,
                )
            except subprocess.TimeoutExpired:
                return JudgeResult(
                    verdict="error",
                    rationale="judge_timeout",
                    error="judge_timeout",
                )
            except OSError as e:
                return JudgeResult(
                    verdict="error",
                    rationale=str(e),
                    error="judge_exec_failed",
                )

            stdout = proc.stdout or ""
            if proc.returncode != 0:
                return JudgeResult(
                    verdict="error",
                    rationale=(proc.stderr or stdout or f"exit {proc.returncode}")[
                        :500
                    ],
                    error="judge_nonzero_exit",
                    raw_stdout=stdout,
                )

            parsed = last_json_object(stdout)
            if not parsed:
                return JudgeResult(
                    verdict="error",
                    rationale="unparseable_judge_stdout",
                    error="judge_unparseable",
                    raw_stdout=stdout,
                )

            verdict = str(parsed.get("verdict") or "error").lower()
            if verdict not in {"clean", "suspicious", "poisoned", "error"}:
                verdict = "error"
            return JudgeResult(
                verdict=verdict,
                score=parsed.get("score"),
                rationale=str(parsed.get("rationale") or ""),
                severity_hint=parsed.get("severity_hint"),
                raw_stdout=stdout,
            )
        finally:
            if prompt_file and prompt_file.exists():
                prompt_file.unlink(missing_ok=True)
