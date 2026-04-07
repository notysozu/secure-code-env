"""
Deterministic grading engine — Steps 12–15.

Scoring breakdown
─────────────────
  vulnerability detection  0.4
  explanation quality      0.3
  fix correctness          0.3
                           ───
                           1.0

All scoring is purely rule-based (no LLM judge) so it is perfectly
reproducible across runs.
"""

from __future__ import annotations

from typing import List

from secure_code_env.models import Action, Reward, RewardBreakdown
from secure_code_env.tasks import TaskDescriptor


# ── Step 13: Vulnerability scoring (weight = 0.4) ───────────────────────
def _score_vulnerabilities(
    action: Action, task: TaskDescriptor
) -> tuple[float, list[str]]:
    """
    Compare predicted vulnerability *types* against expected ones.
    Score = |intersection| / |expected|.
    """
    expected_types = {v["type"].lower() for v in task.expected_vulnerabilities}
    predicted_types = {v.type.lower() for v in action.vulnerabilities}

    if not expected_types:
        return 1.0, ["No vulnerabilities expected — auto-full-marks."]

    matched = expected_types & predicted_types
    score = len(matched) / len(expected_types)

    feedback: list[str] = []
    for vtype in sorted(matched):
        feedback.append(f"  ✓ detected: {vtype}")
    for vtype in sorted(expected_types - matched):
        feedback.append(f"  ✗ missed: {vtype}")
    for vtype in sorted(predicted_types - expected_types):
        feedback.append(f"  ⚠ extra (not penalised): {vtype}")

    return round(score, 4), feedback


# ── Step 14: Explanation scoring (weight = 0.3) ─────────────────────────
def _score_explanation(
    action: Action, task: TaskDescriptor
) -> tuple[float, list[str]]:
    """
    Keyword-based: how many expected keywords appear somewhere in the
    agent's analysis text or vulnerability descriptions.
    """
    blob = action.analysis.lower()
    for v in action.vulnerabilities:
        blob += " " + v.description.lower()
    for f in action.fixes:
        blob += " " + f.explanation.lower()

    expected = task.expected_keywords
    if not expected:
        return 1.0, ["No keywords to check — auto-full-marks."]

    hits = [kw for kw in expected if kw.lower() in blob]
    score = len(hits) / len(expected)

    feedback: list[str] = []
    for kw in expected:
        tag = "✓" if kw.lower() in blob else "✗"
        feedback.append(f"  {tag} keyword '{kw}'")

    return round(score, 4), feedback


# ── Step 15: Fix scoring (weight = 0.3) ─────────────────────────────────
def _score_fixes(
    action: Action, task: TaskDescriptor
) -> tuple[float, list[str]]:
    """
    For each reference fix, check whether the agent proposed a fix that
    targets the same vulnerability type and whose fixed_code is non-empty.
    Bonus points if the fix contains key tokens from the reference.
    """
    ref_fixes = task.reference_fixes
    if not ref_fixes:
        return 1.0, ["No fixes expected — auto-full-marks."]

    agent_fixes_by_type: dict[str, list] = {}
    for fx in action.fixes:
        agent_fixes_by_type.setdefault(fx.target_vulnerability.lower(), []).append(fx)

    total = 0.0
    feedback: list[str] = []

    for ref in ref_fixes:
        ref_type = ref["target_vulnerability"].lower()
        candidates = agent_fixes_by_type.get(ref_type, [])

        if not candidates:
            feedback.append(f"  ✗ no fix for '{ref_type}'")
            continue

        # Take the best candidate
        best = 0.0
        for cand in candidates:
            sub = 0.0
            # 0.4 — provided a fix at all
            if cand.fixed_code.strip():
                sub += 0.4
            # 0.3 — has a meaningful explanation
            if len(cand.explanation.strip()) > 10:
                sub += 0.3
            # 0.3 — fixed_code contains key tokens from reference
            ref_tokens = set(ref["fixed_code"].lower().split())
            cand_tokens = set(cand.fixed_code.lower().split())
            overlap = len(ref_tokens & cand_tokens) / max(len(ref_tokens), 1)
            sub += 0.3 * overlap
            best = max(best, sub)

        total += best
        tag = "✓" if best > 0.5 else "△"
        feedback.append(f"  {tag} fix for '{ref_type}': {best:.2f}")

    score = total / len(ref_fixes)
    return round(min(score, 1.0), 4), feedback


# ═══════════════════════════════════════════════════════════════════════════
# Step 12 — Public API
# ═══════════════════════════════════════════════════════════════════════════

VULN_WEIGHT = 0.4
EXPL_WEIGHT = 0.3
FIX_WEIGHT = 0.3


def grade(action: Action, task: TaskDescriptor, *, done: bool = False) -> Reward:
    """Score an agent Action against a TaskDescriptor.  Deterministic."""

    vuln_score, vuln_fb = _score_vulnerabilities(action, task)
    expl_score, expl_fb = _score_explanation(action, task)
    fix_score, fix_fb = _score_fixes(action, task)

    weighted = (
        VULN_WEIGHT * vuln_score
        + EXPL_WEIGHT * expl_score
        + FIX_WEIGHT * fix_score
    )

    feedback_lines = (
        ["── Vulnerability Detection ──"] + vuln_fb +
        ["── Explanation Quality ──"] + expl_fb +
        ["── Fix Correctness ──"] + fix_fb +
        [f"── Total: {weighted:.4f} ──"]
    )

    return Reward(
        score=round(weighted, 4),
        feedback="\n".join(feedback_lines),
        breakdown=RewardBreakdown(
            vulnerability_score=round(vuln_score, 4),
            explanation_score=round(expl_score, 4),
            fix_score=round(fix_score, 4),
        ),
        done=done,
        task_id=task.task_id,
    )
