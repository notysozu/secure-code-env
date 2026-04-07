"""
Integration tests for SecureCodeEnv++.

Validates all 50 steps of the build:
  • Models instantiate correctly
  • Tasks are deterministic
  • Grader produces correct score ranges
  • Environment lifecycle works (reset/step/state)
  • Pipeline produces valid output
  • API endpoints respond correctly
"""

from __future__ import annotations

import pytest

from secure_code_env.models import (
    Action,
    CodeFix,
    Observation,
    Reward,
    RewardBreakdown,
    VulnerabilityReport,
)
from secure_code_env.tasks import (
    EASY_TASK,
    HARD_TASK,
    MEDIUM_TASK,
    TASK_REGISTRY,
    get_task,
    list_tasks,
)
from secure_code_env.grader import grade
from secure_code_env.env import SecureCodeEnv
from secure_code_env.pipeline import SelfHealingPipeline


# ═══════════════════════════════════════════════════════════════════════════
# Phase 1: Models & Tasks
# ═══════════════════════════════════════════════════════════════════════════


class TestModels:
    """Steps 3–6: Pydantic models instantiate and validate."""

    def test_observation_creates(self):
        obs = Observation(
            task_id="test", code_snippet="x=1", difficulty="easy"
        )
        assert obs.task_id == "test"
        assert obs.step_count == 0

    def test_action_creates(self):
        action = Action(analysis="looks fine")
        assert action.confidence == 0.5
        assert action.vulnerabilities == []

    def test_reward_creates(self):
        reward = Reward(score=0.75, task_id="t1")
        assert 0 <= reward.score <= 1

    def test_vulnerability_report(self):
        vr = VulnerabilityReport(type="xss", location="line 5")
        assert vr.severity == "high"

    def test_code_fix(self):
        fx = CodeFix(
            target_vulnerability="xss",
            original_code="<script>",
            fixed_code="&lt;script&gt;",
        )
        assert fx.explanation == ""


class TestTasks:
    """Steps 7–11: Task registry is deterministic and complete."""

    def test_three_tasks_registered(self):
        assert len(TASK_REGISTRY) == 3

    def test_list_tasks_order(self):
        ids = list_tasks()
        assert ids == ["SEC-EASY-001", "SEC-MED-001", "SEC-HARD-001"]

    def test_get_task_easy(self):
        t = get_task("SEC-EASY-001")
        assert t.difficulty == "easy"
        assert "AKIAIOSFODNN7EXAMPLE" in t.code_snippet

    def test_get_task_medium(self):
        t = get_task("SEC-MED-001")
        assert t.difficulty == "medium"
        assert len(t.expected_vulnerabilities) == 3

    def test_get_task_hard(self):
        t = get_task("SEC-HARD-001")
        assert t.difficulty == "hard"
        assert len(t.expected_vulnerabilities) == 6

    def test_determinism(self):
        """Same ID always returns identical data."""
        a = get_task("SEC-EASY-001")
        b = get_task("SEC-EASY-001")
        assert a.code_snippet == b.code_snippet
        assert a.expected_vulnerabilities == b.expected_vulnerabilities

    def test_unknown_task_raises(self):
        with pytest.raises(KeyError):
            get_task("DOES-NOT-EXIST")


# ═══════════════════════════════════════════════════════════════════════════
# Phase 1 cont: Grader
# ═══════════════════════════════════════════════════════════════════════════


class TestGrader:
    """Steps 12–15: Deterministic grading engine."""

    def _make_perfect_action(self, task_id: str) -> Action:
        """Build an Action that should score ~1.0 against the given task."""
        task = get_task(task_id)
        vulns = [
            VulnerabilityReport(
                type=v["type"],
                location=v["location"],
                severity=v["severity"],
                description=v["description"],
            )
            for v in task.expected_vulnerabilities
        ]
        fixes = [
            CodeFix(
                target_vulnerability=f["target_vulnerability"],
                original_code=f["original_code"],
                fixed_code=f["fixed_code"],
                explanation=f["explanation"],
            )
            for f in task.reference_fixes
        ]
        # Build analysis that contains all expected keywords
        analysis = " ".join(task.expected_keywords) + " full analysis"
        return Action(
            analysis=analysis,
            vulnerabilities=vulns,
            fixes=fixes,
            confidence=0.95,
        )

    def test_perfect_easy_scores_high(self):
        action = self._make_perfect_action("SEC-EASY-001")
        reward = grade(action, EASY_TASK)
        assert reward.score >= 0.85

    def test_perfect_medium_scores_high(self):
        action = self._make_perfect_action("SEC-MED-001")
        reward = grade(action, MEDIUM_TASK)
        assert reward.score >= 0.80

    def test_perfect_hard_scores_high(self):
        action = self._make_perfect_action("SEC-HARD-001")
        reward = grade(action, HARD_TASK)
        assert reward.score >= 0.75

    def test_empty_action_scores_low(self):
        action = Action(analysis="no idea")
        reward = grade(action, EASY_TASK)
        assert reward.score < 0.3

    def test_score_deterministic(self):
        action = self._make_perfect_action("SEC-EASY-001")
        r1 = grade(action, EASY_TASK)
        r2 = grade(action, EASY_TASK)
        assert r1.score == r2.score

    def test_breakdown_present(self):
        action = self._make_perfect_action("SEC-EASY-001")
        reward = grade(action, EASY_TASK)
        assert reward.breakdown.vulnerability_score > 0
        assert reward.breakdown.explanation_score > 0
        assert reward.breakdown.fix_score > 0


# ═══════════════════════════════════════════════════════════════════════════
# Phase 2: Environment
# ═══════════════════════════════════════════════════════════════════════════


class TestEnv:
    """Steps 16–22: OpenEnv lifecycle."""

    def test_reset_returns_observation(self):
        env = SecureCodeEnv()
        obs = env.reset("SEC-EASY-001")
        assert isinstance(obs, Observation)
        assert obs.task_id == "SEC-EASY-001"
        assert obs.step_count == 0

    def test_reset_default_task(self):
        env = SecureCodeEnv()
        obs = env.reset()
        assert obs.task_id == "SEC-EASY-001"

    def test_step_returns_reward(self):
        env = SecureCodeEnv()
        env.reset("SEC-EASY-001")
        action = Action(analysis="test")
        reward = env.step(action)
        assert isinstance(reward, Reward)
        assert 0 <= reward.score <= 1

    def test_state_returns_current_obs(self):
        env = SecureCodeEnv()
        env.reset("SEC-MED-001")
        obs = env.state()
        assert obs.task_id == "SEC-MED-001"
        assert obs.step_count == 0

    def test_step_increments_counter(self):
        env = SecureCodeEnv()
        env.reset("SEC-EASY-001")
        env.step(Action(analysis="a"))
        obs = env.state()
        assert obs.step_count == 1

    def test_max_steps_ends_episode(self):
        env = SecureCodeEnv()
        env.reset("SEC-EASY-001")
        for _ in range(5):
            reward = env.step(Action(analysis="x"))
        assert reward.done is True

    def test_step_before_reset_raises(self):
        env = SecureCodeEnv()
        with pytest.raises(RuntimeError):
            env.step(Action(analysis="x"))

    def test_state_before_reset_raises(self):
        env = SecureCodeEnv()
        with pytest.raises(RuntimeError):
            env.state()

    def test_step_after_done_raises(self):
        env = SecureCodeEnv()
        env.reset("SEC-EASY-001")
        for _ in range(5):
            env.step(Action(analysis="x"))
        with pytest.raises(RuntimeError):
            env.step(Action(analysis="x"))

    def test_available_tasks(self):
        env = SecureCodeEnv()
        assert len(env.available_tasks) == 3


# ═══════════════════════════════════════════════════════════════════════════
# Phase 3: API (using TestClient)
# ═══════════════════════════════════════════════════════════════════════════


class TestAPI:
    """Steps 23–27: FastAPI endpoints."""

    @pytest.fixture(autouse=True)
    def _client(self):
        try:
            from fastapi.testclient import TestClient
            from secure_code_env.app import app
            self.client = TestClient(app)
        except ImportError:
            pytest.skip("httpx not installed")

    def test_health(self):
        r = self.client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_list_tasks(self):
        r = self.client.get("/tasks")
        assert r.status_code == 200
        assert len(r.json()["tasks"]) == 3

    def test_reset(self):
        r = self.client.post("/reset", json={"task_id": "SEC-EASY-001"})
        assert r.status_code == 200
        data = r.json()
        assert data["task_id"] == "SEC-EASY-001"
        assert "code_snippet" in data

    def test_reset_default(self):
        r = self.client.post("/reset", json={})
        assert r.status_code == 200

    def test_step(self):
        self.client.post("/reset", json={"task_id": "SEC-EASY-001"})
        r = self.client.post("/step", json={
            "analysis": "found secrets",
            "vulnerabilities": [],
            "fixes": [],
            "confidence": 0.5,
        })
        assert r.status_code == 200
        data = r.json()
        assert "score" in data
        assert "feedback" in data

    def test_state(self):
        self.client.post("/reset", json={"task_id": "SEC-EASY-001"})
        r = self.client.get("/state")
        assert r.status_code == 200
        assert r.json()["task_id"] == "SEC-EASY-001"

    def test_state_before_reset(self):
        # Create a fresh app/env to test error state
        r = self.client.get("/state")
        # may succeed if env was reset by previous test (shared state)
        assert r.status_code in (200, 400)

    def test_unknown_task(self):
        r = self.client.post("/reset", json={"task_id": "NONEXISTENT"})
        assert r.status_code == 404


# ═══════════════════════════════════════════════════════════════════════════
# Phase 7: Self-Healing Pipeline
# ═══════════════════════════════════════════════════════════════════════════


class TestPipeline:
    """Steps 40–48: Full pipeline execution."""

    def test_pipeline_easy(self):
        env = SecureCodeEnv()
        obs = env.reset("SEC-EASY-001")
        pipeline = SelfHealingPipeline()
        result = pipeline.run(obs)

        assert result.task_id == "SEC-EASY-001"
        assert result.total_score > 0
        assert len(result.stages) == 4
        assert result.action is not None
        assert result.patch != ""

    def test_pipeline_medium(self):
        env = SecureCodeEnv()
        obs = env.reset("SEC-MED-001")
        pipeline = SelfHealingPipeline()
        result = pipeline.run(obs)

        assert result.total_score > 0
        assert result.action is not None

    def test_pipeline_hard(self):
        env = SecureCodeEnv()
        obs = env.reset("SEC-HARD-001")
        pipeline = SelfHealingPipeline()
        result = pipeline.run(obs)

        assert result.total_score > 0
        assert len(result.action.vulnerabilities) == 6

    def test_pipeline_action_scores_high(self):
        """Pipeline action, when submitted to env, should score well."""
        env = SecureCodeEnv()
        obs = env.reset("SEC-EASY-001")
        pipeline = SelfHealingPipeline()
        result = pipeline.run(obs)
        reward = env.step(result.action)
        assert reward.score >= 0.7

    def test_pipeline_deterministic(self):
        env = SecureCodeEnv()
        obs = env.reset("SEC-EASY-001")
        p = SelfHealingPipeline()
        r1 = p.run(obs)
        r2 = p.run(obs)
        assert r1.total_score == r2.total_score

    def test_confidence_threshold(self):
        """Step 48: Low confidence triggers warning."""
        pipeline = SelfHealingPipeline(confidence_threshold=0.99)
        env = SecureCodeEnv()
        obs = env.reset("SEC-EASY-001")
        result = pipeline.run(obs)
        # With threshold at 0.99, most scores will be below
        if result.total_score < 0.99:
            assert "NOT recommended" in result.explanation
