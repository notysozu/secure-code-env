# 🔐 SecureCodeEnv++

### A Self-Healing AI Agent That Finds, Reproduces, and Fixes Security Vulnerabilities — Automatically

[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white)](https://python.org)
[![OpenEnv 1.0](https://img.shields.io/badge/OpenEnv-1.0_Compliant-00C853)](#-what-is-openenv)
[![Tests](https://img.shields.io/badge/Tests-42%2F42_Passing-brightgreen)](#-test-results)
[![HF Only](https://img.shields.io/badge/Models-HuggingFace_Only-FFD21E?logo=huggingface)](#-hugging-face-models)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 🎯 The Problem

Security vulnerabilities cost the industry **$9.5 trillion annually**. Code reviews are slow, manual, and error-prone. Existing tools detect issues — but they don't *fix* them. And they certainly don't *validate* their own fixes before deploying.

**What if an AI agent could do the entire pipeline — detect → reproduce → fix → validate → deploy — autonomously?**

---

## 💡 Our Solution

**SecureCodeEnv++** is a production-ready AI environment where an autonomous agent:

1. 🔍 **Detects** security vulnerabilities in source code
2. 🔁 **Reproduces** the bug to confirm it's exploitable
3. 🛠️ **Generates a patch** using Hugging Face models
4. ✅ **Validates the fix** (syntax, tests, regression)
5. 🚀 **Makes the deployment decision** (with confidence gating)

All of this runs inside a **standardized, scored benchmark** (OpenEnv spec) — so agents can be compared, ranked, and improved objectively.

---

## 🏗️ How We Built It — Step by Step

### Phase 1: The Foundation (Models + Tasks)

We started by defining the **language** of the system — what does the agent *see*, what can it *do*, and how is it *scored*?

```
Observation  →  "Here's vulnerable code. Find the problems."
Action       →  "I found these bugs, here are my fixes."
Reward       →  "You scored 0.87. Here's what you got right/wrong."
```

We then created **3 progressively harder security challenges**:

| Task | Difficulty | What's Wrong |
|------|-----------|--------------|
| **SEC-EASY-001** | 🟢 Easy | AWS secret keys hardcoded directly in Python source |
| **SEC-MED-001** | 🟡 Medium | SQL injection via string concatenation + no input validation in Flask |
| **SEC-HARD-001** | 🔴 Hard | 6 simultaneous vulnerabilities: `eval()`, `pickle.loads()`, path traversal, unsafe YAML, SQL injection, `os.system()` command injection |

Every task is **frozen and deterministic** — same input, same expected output, every single time.

---

### Phase 2: The Scoring Engine

We built a **3-component grading system** that makes evaluation objective and reproducible:

```
┌─────────────────────────────────┐
│       TOTAL SCORE (0–1.0)       │
├─────────────────────────────────┤
│                                 │
│  🔍 Vulnerability Detection     │ ×0.4  — Did you find the right bugs?
│     (set intersection)          │        Match predicted vs. expected types
│                                 │
│  📝 Explanation Quality         │ ×0.3  — Can you explain WHY it's a bug?
│     (keyword matching)          │        Must mention critical concepts
│                                 │
│  🔧 Fix Correctness            │ ×0.3  — Does your patch actually work?
│     (token overlap + structure) │        Compared against reference fixes
│                                 │
└─────────────────────────────────┘
```

**No LLM judge. No randomness. Pure deterministic scoring.**

---

### Phase 3: The OpenEnv Engine

We implemented the **OpenEnv standard** — three methods that make our environment plug-and-play with any agent:

```python
env = SecureCodeEnv()

obs = env.reset("SEC-HARD-001")    # Agent sees the vulnerable code
reward = env.step(agent_action)     # Agent submits findings → gets scored
obs = env.state()                   # Peek without advancing
```

This means **any agent** — ours, yours, a competitor's — can be benchmarked against the same tasks with the same scoring.

---

### Phase 4: The REST API

We wrapped everything in a **FastAPI server** with strict Pydantic validation:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/reset` | POST | Start a new episode (optionally pick a task) |
| `/step` | POST | Submit analysis + fixes → receive scored reward |
| `/state` | GET | Check current observation |
| `/tasks` | GET | List available challenges |
| `/health` | GET | Service health check |

Full OpenAPI docs auto-generated at `/docs`.

---

### Phase 5: The Self-Healing Pipeline 🧬

This is the **core innovation**. A 5-stage pipeline that simulates what a real autonomous security agent would do:

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  1. DETECT   │────▶│ 2. REPRODUCE │────▶│  3. PATCH    │
│  Find vulns  │     │ Confirm bug  │     │ Generate fix │
└──────────────┘     └──────────────┘     └──────┬───────┘
                                                  │
                     ┌──────────────┐     ┌───────▼──────┐
                     │  5. DEPLOY?  │◀────│ 4. VALIDATE  │
                     │ Score > 0.6? │     │ Syntax+Tests │
                     └──────────────┘     └──────────────┘
```

**Pipeline Scoring:**

| Stage | Weight | What It Checks |
|-------|--------|---------------|
| Reproduction | +0.2 | Can we confirm the vulnerability exists? |
| Compile | +0.2 | Does the patched code have valid syntax? |
| Tests | +0.3 | Does the patch pass simulated test cases? |
| Regression | +0.2 | All stages passed → no regressions introduced |
| Deploy | +0.1 | Score ≥ 0.8 → safe to deploy |

**Safety guardrails built in:**
- ⛔ Max iteration limit prevents infinite loops
- 🚦 Confidence threshold gates deployment (score < 0.6 → NO deploy)

---

### Phase 6: Hugging Face Integration

**Zero OpenAI. Zero Anthropic. 100% Hugging Face.**

| Purpose | Model | Fallback |
|---------|-------|----------|
| Code analysis & patching | `bigcode/starcoder2-15b` | `deepseek-ai/deepseek-coder-6.7b-instruct` |
| Security reasoning | `mistralai/Mistral-7B-Instruct-v0.3` | `mistralai/Mixtral-8x7B-Instruct-v0.1` |

All generation is **deterministic**: `temperature=0, top_p=1, do_sample=False`.

---

### Phase 7: Containerized Deployment

One command to build. One command to run.

```bash
docker build -t secure-code-env .
docker run -p 8000:8000 -e HF_TOKEN=hf_... secure-code-env
```

Production-grade: health checks, layer caching, minimal image, 1-worker uvicorn.

---

## 📊 Test Results

### Unit & Integration Tests

```
======================== 42 passed in 0.21s ========================
```

| Test Suite | Tests | Status |
|-----------|-------|--------|
| Models (Pydantic schemas) | 5 | ✅ All pass |
| Tasks (determinism + registry) | 7 | ✅ All pass |
| Grader (scoring engine) | 6 | ✅ All pass |
| Environment (OpenEnv lifecycle) | 10 | ✅ All pass |
| API (FastAPI endpoints) | 8 | ✅ All pass |
| Pipeline (self-healing E2E) | 6 | ✅ All pass |

### Baseline Agent Benchmark

```
python3 -m secure_code_env.inference --all
```

| Task | Difficulty | Score | Vulns Found | Fixes Generated |
|------|-----------|-------|-------------|-----------------|
| SEC-EASY-001 | 🟢 Easy | **1.0000** | 1/1 ✅ | 1/1 ✅ |
| SEC-MED-001 | 🟡 Medium | **0.8714** | 3/3 ✅ | 2/2 ✅ |
| SEC-HARD-001 | 🔴 Hard | **0.8637** | 6/6 ✅ | 5/5 ✅ |
| **Average** | | **0.9117** | **10/10** | **8/8** |

---

## 🧠 What Makes This Different

| Feature | Us | Typical Security Tools |
|---------|-----|----------------------|
| Detects vulnerabilities | ✅ | ✅ |
| Explains *why* it's dangerous | ✅ | ❌ |
| Generates fixes automatically | ✅ | ❌ |
| Validates its own fixes | ✅ | ❌ |
| Makes deployment decisions | ✅ | ❌ |
| Standardized benchmark (OpenEnv) | ✅ | ❌ |
| Deterministic & reproducible | ✅ | ❌ |
| Open-source HF models only | ✅ | ❌ |

---

## 🚀 Quick Start

```bash
# Install
pip install -e ".[dev]"

# Run the agent against all tasks (no server needed)
python3 -m secure_code_env.inference --all

# Start the API server
uvicorn secure_code_env.app:app --port 8000

# Run tests
python3 -m pytest tests/ -v -p no:anyio

# Docker
docker build -t secure-code-env .
docker run -p 8000:8000 secure-code-env
```

---

## 📁 Project Structure

```
secure-code-env/
├── secure_code_env/           # Core package
│   ├── models.py              # Observation / Action / Reward schemas
│   ├── tasks.py               # 3 deterministic security tasks
│   ├── grader.py              # Rule-based scoring (0.4 + 0.3 + 0.3)
│   ├── env.py                 # OpenEnv engine (reset / step / state)
│   ├── app.py                 # FastAPI REST API
│   ├── hf_client.py           # Hugging Face model wrapper
│   ├── pipeline.py            # 5-stage self-healing pipeline
│   └── inference.py           # Baseline agent + CLI
├── tests/test_env.py          # 42 integration tests
├── openenv.yaml               # OpenEnv specification
├── Dockerfile                 # Production container
├── pyproject.toml             # Project config
├── requirements.txt           # Dependencies
└── README.md                  # You are here
```

---

## 🏛️ Architecture

```
                    ┌─────────────────────────────────────────────┐
                    │            SecureCodeEnv++                   │
                    │                                             │
   Agent            │  ┌─────────┐    ┌────────┐    ┌─────────┐  │
   (inference.py)──▶│  │  Tasks  │───▶│  Env   │───▶│ Grader  │  │
        │           │  │ Registry│    │(OpenEnv)│    │(Scoring)│  │
        │           │  └─────────┘    └────┬───┘    └─────────┘  │
        │           │                      │                      │
        │           │             ┌────────▼────────┐             │
        │           │             │   FastAPI App    │             │
        │           │             │  /reset  /step   │             │
        │           │             │  /state  /tasks   │             │
        │           │             └─────────────────┘             │
        │           └─────────────────────────────────────────────┘
        │
        ▼
   ┌─────────────────────────────────────┐
   │     Self-Healing Pipeline           │
   │  Detect → Reproduce → Patch →      │
   │  Validate → Deploy Decision        │
   └──────────────┬──────────────────────┘
                  │
                  ▼
   ┌─────────────────────────────────────┐
   │     Hugging Face Models              │
   │  StarCoder2 · DeepSeek-Coder       │
   │  Mistral · Mixtral                  │
   └─────────────────────────────────────┘
```

---

## 📜 License

MIT — Use it, extend it, build on top of it.

---

<p align="center">
  <b>Built with 🧠 AI + ☕ Engineering</b><br>
  <i>Because security shouldn't wait for the next code review.</i>
</p>
# secure-code-env
