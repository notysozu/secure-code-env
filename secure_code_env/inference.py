"""
Baseline agent / inference loop — Steps 31–35.

Standalone script that:
  1. Connects to the environment API (or runs in-process)
  2. Resets the environment
  3. Runs the self-healing pipeline
  4. Submits the action
  5. Logs [START] / [STEP] / [END]

Usage
─────
  # Against the API
  python -m secure_code_env.inference --api http://localhost:8000

  # In-process (no API server needed)
  python -m secure_code_env.inference
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from typing import Optional

import requests

from secure_code_env.env import SecureCodeEnv
from secure_code_env.models import Action, Observation, Reward
from secure_code_env.pipeline import SelfHealingPipeline
from secure_code_env.hf_client import HFClient

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# Step 31: Agent class
# ═══════════════════════════════════════════════════════════════════════════

class BaselineAgent:
    """
    Deterministic baseline agent that wraps the self-healing pipeline.

    Step 33: deterministic — temperature=0, no sampling.
    Step 35: reproducible — same input always yields same output.
    """

    def __init__(
        self,
        api_url: Optional[str] = None,
        hf_token: Optional[str] = None,
    ) -> None:
        self.api_url = api_url
        self.pipeline = SelfHealingPipeline(
            hf_client=HFClient(token=hf_token) if hf_token else HFClient(),
        )
        # In-process env (used when no API url is provided)
        self._env: Optional[SecureCodeEnv] = None if api_url else SecureCodeEnv()

    # ── Step 32: main loop ────────────────────────────────────────────────
    def run(self, task_id: Optional[str] = None) -> dict:
        """Execute a full episode: reset → pipeline → step → log."""

        # Step 34: [START]
        logger.info("[START] Agent episode — task_id=%s", task_id or "default")
        t0 = time.time()

        # 1. Reset
        obs = self._reset(task_id)
        logger.info(
            "[RESET] task=%s  difficulty=%s  snippet_len=%d",
            obs.task_id, obs.difficulty, len(obs.code_snippet),
        )

        # 2. Run the self-healing pipeline
        logger.info("[PIPELINE] Running self-healing pipeline…")
        pipeline_result = self.pipeline.run(obs)

        if pipeline_result.action is None:
            logger.error("[ERROR] Pipeline produced no action.")
            return {"error": "pipeline_failed"}

        # 3. Step: submit action
        logger.info("[STEP] Submitting action (confidence=%.2f)", pipeline_result.action.confidence)
        reward = self._step(pipeline_result.action)

        # Step 34: [END]
        elapsed = time.time() - t0
        logger.info(
            "[END] score=%.4f  done=%s  elapsed=%.2fs",
            reward.score, reward.done, elapsed,
        )

        return {
            "task_id": obs.task_id,
            "difficulty": obs.difficulty,
            "score": reward.score,
            "breakdown": reward.breakdown.model_dump(),
            "feedback": reward.feedback,
            "done": reward.done,
            "pipeline_score": pipeline_result.total_score,
            "stages": [
                {"stage": s.stage, "passed": s.passed, "score": s.score, "detail": s.detail}
                for s in pipeline_result.stages
            ],
            "elapsed_seconds": round(elapsed, 3),
        }

    # ── Communication layer ────────────────────────────────────────────────
    def _reset(self, task_id: Optional[str]) -> Observation:
        if self.api_url:
            resp = requests.post(
                f"{self.api_url}/reset",
                json={"task_id": task_id},
                timeout=30,
            )
            resp.raise_for_status()
            return Observation(**resp.json())
        else:
            assert self._env is not None
            return self._env.reset(task_id)

    def _step(self, action: Action) -> Reward:
        if self.api_url:
            resp = requests.post(
                f"{self.api_url}/step",
                json=action.model_dump(),
                timeout=30,
            )
            resp.raise_for_status()
            return Reward(**resp.json())
        else:
            assert self._env is not None
            return self._env.step(action)


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(description="SecureCodeEnv++ Baseline Agent")
    parser.add_argument("--api", type=str, default=None, help="API base URL")
    parser.add_argument("--task", type=str, default=None, help="Task ID to run")
    parser.add_argument("--all", action="store_true", help="Run all tasks")
    parser.add_argument("--hf-token", type=str, default=None, help="HF API token")
    args = parser.parse_args()

    agent = BaselineAgent(api_url=args.api, hf_token=args.hf_token)

    if args.all:
        from secure_code_env.tasks import list_tasks
        results = []
        for tid in list_tasks():
            r = agent.run(task_id=tid)
            results.append(r)
            print(json.dumps(r, indent=2))
            print("─" * 60)
        avg = sum(r["score"] for r in results) / len(results)
        logger.info("[SUMMARY] Average score across %d tasks: %.4f", len(results), avg)
    else:
        result = agent.run(task_id=args.task)
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
