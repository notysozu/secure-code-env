"""
Hugging Face model client — Steps 36–39.

Wraps the ``huggingface_hub.InferenceClient`` to provide deterministic,
temperature-0 access to code and reasoning models.

Supported model families
────────────────────────
  Code:      bigcode/starcoder2-15b, deepseek-ai/deepseek-coder-6.7b-instruct
  Reasoning: mistralai/Mistral-7B-Instruct-v0.3, mistralai/Mixtral-8x7B-Instruct-v0.1

Set the ``HF_TOKEN`` environment variable or pass the token at init.
"""

from __future__ import annotations

import os
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


# ── Step 39: Deterministic generation config ────────────────────────────
@dataclass(frozen=True)
class GenerationConfig:
    """Frozen config that guarantees reproducibility."""

    temperature: float = 0.0
    top_p: float = 1.0
    max_new_tokens: int = 1024
    repetition_penalty: float = 1.0
    do_sample: bool = False


# Default models
DEFAULT_CODE_MODEL = "bigcode/starcoder2-15b"
DEFAULT_REASONING_MODEL = "mistralai/Mistral-7B-Instruct-v0.3"

# Alternate models
ALTERNATE_MODELS = {
    "code": [
        "bigcode/starcoder2-15b",
        "deepseek-ai/deepseek-coder-6.7b-instruct",
    ],
    "reasoning": [
        "mistralai/Mistral-7B-Instruct-v0.3",
        "mistralai/Mixtral-8x7B-Instruct-v0.1",
    ],
}


class HFClient:
    """
    Wrapper around Hugging Face Inference API.

    Step 36: init / connectivity
    Step 37: code model support
    Step 38: reasoning model support
    Step 39: deterministic config enforcement
    """

    def __init__(
        self,
        token: Optional[str] = None,
        code_model: str = DEFAULT_CODE_MODEL,
        reasoning_model: str = DEFAULT_REASONING_MODEL,
        config: GenerationConfig = GenerationConfig(),
    ) -> None:
        self.token = token or os.environ.get("HF_TOKEN", "")
        self.code_model = code_model
        self.reasoning_model = reasoning_model
        self.config = config
        self._client = None  # lazy init

        if not self.token:
            logger.warning(
                "HF_TOKEN not set — HF Inference API calls will fail. "
                "Set HF_TOKEN env-var or pass token= to HFClient()."
            )

    # ── lazy Inference client ──────────────────────────────────────────────
    def _get_client(self):
        if self._client is None:
            try:
                from huggingface_hub import InferenceClient
                self._client = InferenceClient(token=self.token)
            except ImportError:
                raise RuntimeError(
                    "Install huggingface_hub: pip install huggingface_hub"
                )
        return self._client

    # ── Step 37: Code model ────────────────────────────────────────────────
    def generate_code(self, prompt: str, model: Optional[str] = None) -> str:
        """Use a code-specialised HF model to generate / fix code."""
        model = model or self.code_model
        return self._generate(prompt, model)

    # ── Step 38: Reasoning model ───────────────────────────────────────────
    def generate_reasoning(self, prompt: str, model: Optional[str] = None) -> str:
        """Use a reasoning HF model for analysis / explanation."""
        model = model or self.reasoning_model
        return self._generate(prompt, model)

    # ── Internal generation ────────────────────────────────────────────────
    def _generate(self, prompt: str, model: str) -> str:
        client = self._get_client()
        logger.info("HF Inference → model=%s  tokens=%d", model, self.config.max_new_tokens)
        try:
            response = client.text_generation(
                prompt,
                model=model,
                temperature=self.config.temperature,
                top_p=self.config.top_p,
                max_new_tokens=self.config.max_new_tokens,
                repetition_penalty=self.config.repetition_penalty,
                do_sample=self.config.do_sample,
            )
            return response
        except Exception as exc:
            logger.error("HF Inference error: %s", exc)
            return f"[HF_ERROR] {exc}"

    # ── Convenience: build a security-analysis prompt ─────────────────────
    def build_analysis_prompt(self, code: str, language: str = "python") -> str:
        return (
            f"You are a senior security engineer. Analyse the following {language} code "
            f"for vulnerabilities. List each vulnerability with its type, location, "
            f"severity, and a brief explanation. Then propose fixes.\n\n"
            f"```{language}\n{code}\n```\n\n"
            f"Respond in structured format:\n"
            f"VULNERABILITIES:\n- type: ..., location: ..., severity: ..., description: ...\n\n"
            f"FIXES:\n- target: ..., original: ..., fixed: ..., explanation: ...\n"
        )

    def build_fix_prompt(self, code: str, vulnerability: str, language: str = "python") -> str:
        return (
            f"Fix the following {vulnerability} vulnerability in this {language} code. "
            f"Return ONLY the corrected code.\n\n"
            f"```{language}\n{code}\n```\n"
        )
