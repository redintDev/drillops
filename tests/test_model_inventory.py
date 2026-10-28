"""Unit tests for Dynamic Model Inventory Discovery & Routing Engine."""

import json
import os
import sys
import tempfile
import pytest

WORKSPACE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if WORKSPACE_ROOT not in sys.path:
    sys.path.insert(0, WORKSPACE_ROOT)

from scripts.model_inventory import (
    POOL_CLAUDE_GPT,
    POOL_GEMINI,
    build_inventory_structure,
    classify_model,
    get_model_selection,
    get_replacement_model,
    is_model_valid,
    parse_model_listing,
    rank_pool_models,
    sync_quota_state_models,
)


def test_classify_model_gemini():
    info = classify_model("gemini-3.8-flash-high", "Gemini 3.8 Flash (High)")
    assert info["pool"] == POOL_GEMINI
    assert info["family"] == "google"
    assert info["is_flash"] is True
    assert info["is_pro"] is False
    assert info["tier_weight"] == 3
    assert info["version_score"] == 308


def test_classify_model_claude_opus():
    info = classify_model("claude-opus-4-6-thinking", "Claude Opus 4.6 (Thinking)")
    assert info["pool"] == POOL_CLAUDE_GPT
    assert info["family"] == "anthropic"
    assert info["is_opus"] is True
    assert info["is_thinking"] is True
    assert info["version_score"] == 406


def test_classify_model_gpt():
    info = classify_model("gpt-oss-120b-medium", "GPT-OSS 120B (Medium)")
    assert info["pool"] == POOL_CLAUDE_GPT
    assert info["is_gpt"] is True
    assert info["tier_weight"] == 2


def test_parse_model_listing():
    sample_output = """⠋ Fetching available models...
gemini-3.8-flash-high\tGemini 3.8 Flash (High)
gemini-3.8-flash-medium\tGemini 3.8 Flash (Medium)
claude-opus-4-6-thinking\tClaude Opus 4.6 (Thinking)
claude-sonnet-4-6\tClaude Sonnet 4.6 (Thinking)
gpt-oss-120b-medium\tGPT-OSS 120B (Medium)
Fetching available models...
"""
    models = parse_model_listing(sample_output)
    assert len(models) == 5
    ids = [m["id"] for m in models]
    assert "gemini-3.8-flash-high" in ids
    assert "claude-opus-4-6-thinking" in ids
    assert "gpt-oss-120b-medium" in ids


def test_rank_pool_models_gemini():
    models = [
        classify_model("gemini-3.8-flash-low", "Gemini 3.8 Flash (Low)"),
        classify_model("gemini-3.8-flash-high", "Gemini 3.8 Flash (High)"),
        classify_model("gemini-3.8-flash-medium", "Gemini 3.8 Flash (Medium)"),
    ]
    ranked = rank_pool_models(models, POOL_GEMINI, "routine")
    assert ranked[0]["id"] == "gemini-3.8-flash-high"
    assert ranked[-1]["id"] == "gemini-3.8-flash-low"


def test_rank_pool_models_claude():
    models = [
        classify_model("gpt-oss-120b-medium", "GPT-OSS 120B (Medium)"),
        classify_model("claude-sonnet-4-6", "Claude Sonnet 4.6 (Thinking)"),
        classify_model("claude-opus-4-6-thinking", "Claude Opus 4.6 (Thinking)"),
    ]
    # For frontier deep reasoning, Opus thinking should rank first
    ranked = rank_pool_models(models, POOL_CLAUDE_GPT, "frontier")
    assert ranked[0]["id"] == "claude-opus-4-6-thinking"
    assert ranked[1]["id"] == "claude-sonnet-4-6"
    assert ranked[2]["id"] == "gpt-oss-120b-medium"

    # For routine fallback in Claude/GPT pool, GPT-OSS should rank first
    ranked_routine = rank_pool_models(models, POOL_CLAUDE_GPT, "routine")
    assert ranked_routine[0]["id"] == "gpt-oss-120b-medium"


def test_build_inventory_structure():
    models = [
        classify_model("gemini-3.8-flash-high", "Gemini 3.8 Flash (High)"),
        classify_model("gemini-3.8-flash-medium", "Gemini 3.8 Flash (Medium)"),
        classify_model("claude-opus-4-6-thinking", "Claude Opus 4.6 (Thinking)"),
        classify_model("claude-sonnet-4-6", "Claude Sonnet 4.6 (Thinking)"),
        classify_model("gpt-oss-120b-medium", "GPT-OSS 120B (Medium)"),
    ]
    inv = build_inventory_structure(models)
    assert inv["total_available"] == 5

    # Routine tier uses Flash in gemini-pool
    assert inv["selection"]["routine"]["primary_pool"] == POOL_GEMINI
    assert inv["selection"]["routine"]["primary_model"] == "gemini-3.8-flash-high"
    assert inv["selection"]["routine"]["fallback_pool"] == POOL_CLAUDE_GPT

    # Frontier tier uses Opus Thinking in claude-gpt-pool
    assert inv["selection"]["frontier"]["primary_pool"] == POOL_CLAUDE_GPT
    assert inv["selection"]["frontier"]["primary_model"] == "claude-opus-4-6-thinking"
    assert inv["selection"]["frontier"]["fallback_pool"] == POOL_GEMINI
    assert inv["selection"]["frontier"]["fallback_model"] == "gemini-3.8-flash-high"


def test_is_model_valid():
    assert is_model_valid("gemini-3.8-flash-high") is True
    assert is_model_valid("claude-opus-4-6-thinking") is True
    # Deprecated model must NOT be valid
    assert is_model_valid("gemini-3.1-pro-high") is False
    assert is_model_valid("non-existent-model-xyz") is False


def test_get_model_selection():
    routine_sel = get_model_selection("routine")
    assert routine_sel["primary_pool"] == POOL_GEMINI
    assert "flash" in routine_sel["primary_model"]

    frontier_sel = get_model_selection("frontier")
    assert frontier_sel["primary_pool"] == POOL_CLAUDE_GPT
    assert "claude" in frontier_sel["primary_model"]
