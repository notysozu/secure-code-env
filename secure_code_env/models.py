"""
Pydantic models for the OpenEnv observation / action / reward contract.

Steps 3-6 of the build plan.
"""

from __future__ import annotations

from typing import List, Optional
from pydantic import BaseModel, Field


# ── Step 4: Observation Model ────────────────────────────────────────────────
class Observation(BaseModel):
    """What the agent *sees* when it enters or re-enters the environment."""

    task_id: str = Field(
        ..., description="Unique, deterministic identifier for the task."
    )
    code_snippet: str = Field(
        ..., description="The source code the agent must analyse."
    )
    language: str = Field(
        default="python", description="Programming language of the snippet."
    )
    difficulty: str = Field(
        ..., description="One of: easy, medium, hard."
    )
    step_count: int = Field(
        default=0, description="How many steps the agent has taken so far."
    )
    max_steps: int = Field(
        default=5, description="Maximum allowed steps before the episode ends."
    )
    description: str = Field(
        default="", description="Human-readable task description."
    )


# ── Step 5: Action Model ────────────────────────────────────────────────────
class VulnerabilityReport(BaseModel):
    """A single reported vulnerability."""

    type: str = Field(
        ..., description="CWE-style label, e.g. 'hardcoded-secret'."
    )
    location: str = Field(
        ..., description="Line or range where the vulnerability lives."
    )
    severity: str = Field(
        default="high", description="low | medium | high | critical"
    )
    description: str = Field(
        default="", description="Free-text explanation of the issue."
    )


class CodeFix(BaseModel):
    """A proposed fix for a vulnerability."""

    target_vulnerability: str = Field(
        ..., description="The vulnerability type this fix addresses."
    )
    original_code: str = Field(
        ..., description="The code being replaced."
    )
    fixed_code: str = Field(
        ..., description="The replacement code."
    )
    explanation: str = Field(
        default="", description="Why this fix works."
    )


class Action(BaseModel):
    """What the agent *does* — analyse, report, and fix."""

    analysis: str = Field(
        ..., description="Free-text security analysis of the snippet."
    )
    vulnerabilities: List[VulnerabilityReport] = Field(
        default_factory=list,
        description="List of detected vulnerabilities.",
    )
    fixes: List[CodeFix] = Field(
        default_factory=list,
        description="List of proposed code fixes.",
    )
    confidence: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Agent's self-reported confidence in its answer.",
    )


# ── Step 6: Reward Model ────────────────────────────────────────────────────
class RewardBreakdown(BaseModel):
    """Granular sub-scores so the agent can learn what went right/wrong."""

    vulnerability_score: float = Field(
        default=0.0, description="Score for vulnerability detection (weight 0.4)."
    )
    explanation_score: float = Field(
        default=0.0, description="Score for explanation quality (weight 0.3)."
    )
    fix_score: float = Field(
        default=0.0, description="Score for fix correctness (weight 0.3)."
    )


class Reward(BaseModel):
    """What the environment returns after a step."""

    score: float = Field(
        ..., ge=0.0, le=1.0, description="Weighted total score."
    )
    feedback: str = Field(
        default="", description="Human-readable feedback."
    )
    breakdown: RewardBreakdown = Field(
        default_factory=RewardBreakdown,
        description="Per-component scores.",
    )
    done: bool = Field(
        default=False, description="Whether the episode has ended."
    )
    task_id: str = Field(
        default="", description="The task that was evaluated."
    )
