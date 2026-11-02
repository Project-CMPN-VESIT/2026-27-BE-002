from __future__ import annotations

import ast
import json
import os
import threading
import time

from quallki_agentic.config import Settings
from quallki_agentic.progress import Status, get_progress_logger


# ── Global Rate Limiter ─────────────────────────────────────────────────
# Gemini free tier: ~15 RPM for gemini-3.5/3.6-flash.
# We enforce a minimum gap of 4 seconds between consecutive calls so
# that 4 agents (triage/response/compliance/cvss) don't fire together.
_MIN_CALL_GAP_SECONDS = 4.0
_last_call_time = 0.0
_rate_lock = threading.Lock()


def _wait_for_rate_limit(agent_name: str) -> None:
    """Block until the minimum gap between LLM calls has elapsed."""
    global _last_call_time
    logger = get_progress_logger()

    with _rate_lock:
        now = time.time()
        elapsed = now - _last_call_time
        if elapsed < _MIN_CALL_GAP_SECONDS:
            wait = _MIN_CALL_GAP_SECONDS - elapsed
            logger.emit("current", agent_name, "llm_call", Status.RUNNING,
                         f"Rate-limiting: waiting {wait:.1f}s before LLM call...")
            time.sleep(wait)
        _last_call_time = time.time()


# ── Response Text Extraction ────────────────────────────────────────────
def _extract_text(content) -> str:
    """Extract plain text from LLM response content (handles various formats)."""
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        # Gemini returns [{'type': 'text', 'text': '...'}]
        parts = []
        for item in content:
            if isinstance(item, dict) and "text" in item:
                parts.append(str(item["text"]))
            elif isinstance(item, str):
                parts.append(item)
        return "\n".join(parts).strip()
    return str(content).strip()


# ── Invoke with Retry ───────────────────────────────────────────────────
def _try_invoke(llm, prompt: str, agent_name: str, provider: str) -> str | None:
    """Attempt to invoke an LLM with retry for rate-limit and overload errors."""
    logger = get_progress_logger()
    max_retries = 3
    delays = [5, 15, 30]  # backoff seconds

    for attempt in range(max_retries + 1):
        # Enforce rate limit before each attempt
        _wait_for_rate_limit(agent_name)

        try:
            response = llm.invoke(prompt)
            raw = _extract_text(response.content)
            return raw
        except Exception as e:
            err_str = str(e)
            is_retryable = any(tok in err_str for tok in (
                "429", "RESOURCE_EXHAUSTED", "503", "UNAVAILABLE",
                "overloaded", "high demand", "temporarily"
            ))

            if is_retryable and attempt < max_retries:
                wait = delays[attempt]
                logger.emit("current", agent_name, "llm_call", Status.RUNNING,
                             f"{provider} overloaded, retrying in {wait}s "
                             f"(attempt {attempt+2}/{max_retries+1})...")
                print(f"{provider} overloaded, retrying in {wait}s...")
                time.sleep(wait)
                continue

            logger.emit("current", agent_name, "llm_call", Status.ERROR,
                         f"{provider} invocation failed: {e}")
            print(f"{provider} invocation error: {e}")
            return None


# ── Main Entry Point ────────────────────────────────────────────────────
def invoke_llm(prompt: str, agent_name: str = "unknown") -> dict[str, object] | None:
    """Invoke the configured LLM and return parsed JSON.

    Uses Gemini as the primary LLM. NVIDIA Nemotron is commented out.
    Applies global rate-limiting to avoid overloading the free tier.
    """
    settings = Settings.from_env()
    logger = get_progress_logger()

    raw_response = None

    # # ── NVIDIA (disabled) ────────────────────────────────────────────
    # if os.getenv("NVIDIA_API_KEY"):
    #     try:
    #         logger.emit("current", agent_name, "llm_call", Status.RUNNING,
    #                      f"Calling NVIDIA Nemotron for {agent_name}...")
    #         from langchain_nvidia_ai_endpoints import ChatNVIDIA
    #         nvidia_llm = ChatNVIDIA(
    #             model="nvidia/nemotron-3-ultra-550b-a55b",
    #             nvidia_api_key=os.environ["NVIDIA_API_KEY"],
    #             temperature=0.0
    #         )
    #         raw_response = _try_invoke(nvidia_llm, prompt, agent_name, "NVIDIA")
    #     except Exception as e:
    #         logger.emit("current", agent_name, "llm_call", Status.ERROR,
    #                      f"NVIDIA LLM init failed: {e}")
    #         print(f"Failed to load NVIDIA LLM: {e}")

    # ── Gemini (primary) ────────────────────────────────────────────────
    if raw_response is None and os.getenv("GEMINI_API_KEY"):
        try:
            logger.emit("current", agent_name, "llm_call", Status.RUNNING,
                         f"Calling Gemini ({settings.gemini_model}) for {agent_name}...")
            from langchain_google_genai import ChatGoogleGenerativeAI
            gemini_llm = ChatGoogleGenerativeAI(
                model=settings.gemini_model,
                google_api_key=os.environ["GEMINI_API_KEY"],
                temperature=0.0,
            )
            raw_response = _try_invoke(gemini_llm, prompt, agent_name, "Gemini")
        except Exception as e:
            logger.emit("current", agent_name, "llm_call", Status.ERROR,
                         f"Gemini LLM init failed: {e}")
            print(f"Failed to load Gemini LLM: {e}")

    if raw_response is None:
        logger.emit("current", agent_name, "llm_call", Status.ERROR,
                     "All LLM providers failed or unavailable")
        return None

    # ── Parse JSON from response ────────────────────────────────────────
    try:
        start, end = raw_response.find("{"), raw_response.rfind("}")
        if start == -1 or end == -1:
            logger.emit("current", agent_name, "llm_call", Status.ERROR,
                         "LLM response did not contain valid JSON")
            return None

        try:
            parsed = json.loads(raw_response[start : end + 1])
        except json.JSONDecodeError:
            try:
                parsed = ast.literal_eval(raw_response[start : end + 1])
            except (SyntaxError, ValueError):
                logger.emit("current", agent_name, "llm_call", Status.ERROR,
                             "Failed to parse LLM response as JSON")
                return None

        if isinstance(parsed, dict):
            logger.emit("current", agent_name, "llm_call", Status.COMPLETED,
                         f"LLM response received for {agent_name}")
            return parsed

        logger.emit("current", agent_name, "llm_call", Status.ERROR,
                     "LLM response was not a JSON object")
        return None
    except Exception as e:
        logger.emit("current", agent_name, "llm_call", Status.ERROR,
                     f"LLM extraction error: {e}")
        print(f"LLM extraction error: {e}")
        return None


def get_structured_llm(agent_name: str = "unknown"):
    """Return a raw LLM instance for structured output use."""
    settings = Settings.from_env()
    logger = get_progress_logger()

    # # ── NVIDIA (disabled) ────────────────────────────────────────────
    # if os.getenv("NVIDIA_API_KEY"):
    #     try:
    #         logger.emit("current", agent_name, "llm_init", Status.RUNNING,
    #                      f"Initializing NVIDIA Nemotron for {agent_name}...")
    #         from langchain_nvidia_ai_endpoints import ChatNVIDIA
    #         llm = ChatNVIDIA(
    #             model="nvidia/nemotron-3-ultra-550b-a55b",
    #             nvidia_api_key=os.environ["NVIDIA_API_KEY"],
    #             temperature=0.0
    #         )
    #         logger.emit("current", agent_name, "llm_init", Status.COMPLETED,
    #                      f"NVIDIA Nemotron ready for {agent_name}")
    #         return llm
    #     except Exception as e:
    #         logger.emit("current", agent_name, "llm_init", Status.ERROR,
    #                      f"NVIDIA init failed: {e}")

    if os.getenv("GEMINI_API_KEY"):
        try:
            logger.emit("current", agent_name, "llm_init", Status.RUNNING,
                         f"Initializing Gemini ({settings.gemini_model}) for {agent_name}...")
            from langchain_google_genai import ChatGoogleGenerativeAI
            llm = ChatGoogleGenerativeAI(
                model=settings.gemini_model,
                google_api_key=os.environ["GEMINI_API_KEY"],
                temperature=0.0,
            )
            logger.emit("current", agent_name, "llm_init", Status.COMPLETED,
                         f"Gemini ready for {agent_name}")
            return llm
        except Exception as e:
            logger.emit("current", agent_name, "llm_init", Status.ERROR,
                         f"Gemini init failed: {e}")

    logger.emit("current", agent_name, "llm_init", Status.ERROR,
                 "No LLM provider available")
    return None


# Backward compatibility alias
invoke_gemini = invoke_llm
