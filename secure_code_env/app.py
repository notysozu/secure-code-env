"""
FastAPI application — Steps 23–27.

Three endpoints that form the OpenEnv REST contract:
  POST /reset   → Observation
  POST /step    → Reward
  GET  /state   → Observation
"""

from __future__ import annotations

from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from secure_code_env.env import SecureCodeEnv
from secure_code_env.models import Action, Observation, Reward

# ── Step 23: Create FastAPI app ────────────────────────────────────────────
app = FastAPI(
    title="SecureCodeEnv++",
    version="1.0.0",
    description=(
        "An OpenEnv-compatible AI environment for security vulnerability "
        "detection, bug reproduction, and self-healing patch generation."
    ),
)

# Single global environment instance (stateful, single-tenant)
_env = SecureCodeEnv()


# ── Request schemas ────────────────────────────────────────────────────────
class ResetRequest(BaseModel):
    task_id: Optional[str] = None


# ── Step 24: /reset endpoint ──────────────────────────────────────────────
@app.post("/reset", response_model=Observation, tags=["OpenEnv"])
def reset(body: ResetRequest = ResetRequest()) -> Observation:
    """
    Start or restart an episode.
    Optionally pass a ``task_id`` to select a specific task.
    """
    try:
        return _env.reset(task_id=body.task_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Unknown task_id: {body.task_id}")


# ── Step 25: /step endpoint ──────────────────────────────────────────────
@app.post("/step", response_model=Reward, tags=["OpenEnv"])
def step(action: Action) -> Reward:
    """
    Submit an agent action and receive a graded reward.
    """
    try:
        return _env.step(action)
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# ── Step 26: /state endpoint ─────────────────────────────────────────────
@app.get("/state", response_model=Observation, tags=["OpenEnv"])
def get_state() -> Observation:
    """
    Return the current observation without advancing the episode.
    """
    try:
        return _env.state()
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# ── Step 27: Extra utility endpoints ─────────────────────────────────────
@app.get("/tasks", tags=["Utility"])
def list_tasks():
    """Return the list of available task IDs."""
    return {"tasks": _env.available_tasks}


@app.get("/health", tags=["Utility"])
def health():
    return {"status": "ok", "version": "1.0.0"}
