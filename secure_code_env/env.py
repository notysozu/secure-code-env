"""
OpenEnv-compatible environment — Steps 16–22.

Implements the three canonical methods every OpenEnv must expose:
  • reset(task_id?) → Observation
  • step(action)   → Reward
  • state()        → Observation
"""

from __future__ import annotations

from typing import Optional

from secure_code_env.models import Action, Observation, Reward
from secure_code_env.grader import grade
from secure_code_env.tasks import (
    TASK_ORDER,
    TaskDescriptor,
    get_task,
    list_tasks,
)


class SecureCodeEnv:
    """
    A stateful, single-episode environment for security code review.

    Lifecycle
    ─────────
      obs = env.reset("SEC-EASY-001")   # start episode
      reward = env.step(action)          # agent acts
      obs = env.state()                  # peek at current state
    """

    # ── Step 17: __init__ ──────────────────────────────────────────────────
    def __init__(self) -> None:
        self._task: Optional[TaskDescriptor] = None
        self._step_count: int = 0
        self._done: bool = False
        self._last_reward: Optional[Reward] = None
        self._available_tasks = list_tasks()

    # ── Step 18: reset ─────────────────────────────────────────────────────
    def reset(self, task_id: Optional[str] = None) -> Observation:
        """
        Start (or restart) an episode.

        Parameters
        ----------
        task_id : str, optional
            If omitted the first task in canonical order is used.
        """
        if task_id is None:
            task_id = self._available_tasks[0]

        self._task = get_task(task_id)
        self._step_count = 0  # Step 20: reset counter
        self._done = False
        self._last_reward = None

        return self._make_observation()

    # ── Step 19: step ──────────────────────────────────────────────────────
    def step(self, action: Action) -> Reward:
        """
        Accept an agent action, grade it, and return the reward.

        The episode ends when:
          • the agent has reached max_steps, OR
          • the agent's score ≥ 0.9 (early stop on success).
        """
        if self._task is None:
            raise RuntimeError("Call reset() before step().")
        if self._done:
            raise RuntimeError("Episode already finished. Call reset().")

        # Step 20: increment
        self._step_count += 1
        done = self._step_count >= self._task.max_steps

        reward = grade(action, self._task, done=done)

        # Early-stop on high accuracy
        if reward.score >= 0.9:
            reward = reward.model_copy(update={"done": True})

        self._done = reward.done
        self._last_reward = reward
        return reward

    # ── Step 21: state ─────────────────────────────────────────────────────
    def state(self) -> Observation:
        """Return the current observation without advancing the episode."""
        if self._task is None:
            raise RuntimeError("Call reset() before state().")
        return self._make_observation()

    # ── helpers ────────────────────────────────────────────────────────────
    def _make_observation(self) -> Observation:
        assert self._task is not None
        return Observation(
            task_id=self._task.task_id,
            code_snippet=self._task.code_snippet,
            language=self._task.language,
            difficulty=self._task.difficulty,
            step_count=self._step_count,
            max_steps=self._task.max_steps,
            description=self._task.description,
        )

    @property
    def done(self) -> bool:
        return self._done

    @property
    def available_tasks(self) -> list[str]:
        return list(self._available_tasks)
