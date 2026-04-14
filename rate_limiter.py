"""
rate_limiter.py — MedScribe RCM call-rate enforcement
======================================================
Free tier  : 20 tool calls per api_key per UTC day.
Paid tier  : unlimited.

Storage    : Supabase free tier — api_users table.
             NO PHI stored. Only api_key_hash + plan_tier + daily_count + reset_date.

Supabase table DDL (run once in Supabase SQL editor):
------------------------------------------------------
create table if not exists api_users (
    id               uuid primary key default gen_random_uuid(),
    api_key_hash     text unique not null,
    plan_tier        text not null default 'free',
    daily_count      integer not null default 0,
    reset_date       date not null default current_date,
    created_at       timestamptz default now(),
    updated_at       timestamptz default now()
);
create index if not exists idx_api_users_key on api_users(api_key_hash);
"""

import hashlib
import logging
import os
from datetime import date, timezone, datetime
from typing import Optional

logger = logging.getLogger("medscribe.rate_limiter")

FREE_TIER_DAILY_LIMIT = 20


class RateLimitExceeded(Exception):
    """Raised when a free-tier key has exhausted its daily quota."""
    pass


class RateLimiterError(Exception):
    """Raised when Supabase is unreachable and we cannot enforce limits."""
    pass


def _hash_key(api_key: str) -> str:
    """SHA-256 hash of the API key — what we store, never the raw key."""
    return hashlib.sha256(api_key.encode()).hexdigest()


def _today_utc() -> str:
    return date.today().isoformat()


def _get_supabase():
    """Reuse the singleton already initialised in consent.py."""
    from consent import _get_supabase as _consent_supabase
    return _consent_supabase()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_and_increment(api_key: str) -> dict:
    """
    Check rate limit for api_key and increment the daily counter.

    Returns a dict with plan info for the caller to use.
    Raises RateLimitExceeded if free tier is exhausted.
    Raises RateLimiterError if Supabase is unreachable.

    Returns
    -------
    {
        "plan_tier":     "free" | "paid" | "enterprise",
        "daily_count":   int,   # count AFTER this call
        "daily_limit":   int | None,   # None = unlimited
        "calls_remaining": int | None
    }
    """
    key_hash = _hash_key(api_key)
    today = _today_utc()

    try:
        sb = _get_supabase()

        # Fetch existing row
        result = sb.table("api_users") \
            .select("id, plan_tier, daily_count, reset_date") \
            .eq("api_key_hash", key_hash) \
            .maybe_single() \
            .execute()

        row = result.data

        if row is None:
            # New key — create free tier record
            new_row = {
                "api_key_hash": key_hash,
                "plan_tier":    "free",
                "daily_count":  1,
                "reset_date":   today,
            }
            sb.table("api_users").insert(new_row).execute()
            logger.info("rate_limiter: new free-tier key registered (hash prefix: %s)", key_hash[:8])
            return {
                "plan_tier":       "free",
                "daily_count":     1,
                "daily_limit":     FREE_TIER_DAILY_LIMIT,
                "calls_remaining": FREE_TIER_DAILY_LIMIT - 1,
            }

        plan_tier = row["plan_tier"]
        reset_date = row["reset_date"]

        # Paid and enterprise tiers — increment but never block
        if plan_tier in ("paid", "enterprise"):
            new_count = row["daily_count"] + 1
            _reset_or_increment(sb, key_hash, new_count, reset_date, today)
            logger.info("rate_limiter: %s tier call #%d (hash prefix: %s)",
                        plan_tier, new_count, key_hash[:8])
            return {
                "plan_tier":       plan_tier,
                "daily_count":     new_count,
                "daily_limit":     None,
                "calls_remaining": None,
            }

        # Free tier — check limit
        if reset_date != today:
            # New UTC day — reset counter
            new_count = 1
            sb.table("api_users") \
                .update({"daily_count": new_count, "reset_date": today}) \
                .eq("api_key_hash", key_hash) \
                .execute()
        else:
            new_count = row["daily_count"] + 1
            if new_count > FREE_TIER_DAILY_LIMIT:
                logger.warning(
                    "rate_limiter: FREE tier limit reached for hash prefix %s", key_hash[:8]
                )
                raise RateLimitExceeded(
                    f"Free tier limit of {FREE_TIER_DAILY_LIMIT} calls/day reached. "
                    f"Upgrade to paid tier at medscribepro.in for unlimited access."
                )
            sb.table("api_users") \
                .update({"daily_count": new_count}) \
                .eq("api_key_hash", key_hash) \
                .execute()

        remaining = max(0, FREE_TIER_DAILY_LIMIT - new_count)
        logger.info("rate_limiter: free tier call %d/%d (hash prefix: %s)",
                    new_count, FREE_TIER_DAILY_LIMIT, key_hash[:8])
        return {
            "plan_tier":       "free",
            "daily_count":     new_count,
            "daily_limit":     FREE_TIER_DAILY_LIMIT,
            "calls_remaining": remaining,
        }

    except RateLimitExceeded:
        raise
    except Exception as exc:
        # Supabase unreachable — fail open with a warning rather than
        # blocking legitimate users. Log prominently for monitoring.
        logger.error(
            "rate_limiter: Supabase unreachable — rate limit NOT enforced: %s", exc
        )
        raise RateLimiterError(
            f"Rate limiter temporarily unavailable: {exc}"
        ) from exc


def get_plan_tier(api_key: str) -> str:
    """
    Return the plan tier for an API key without incrementing the counter.
    Returns 'free' if the key is not found.
    """
    key_hash = _hash_key(api_key)
    try:
        sb = _get_supabase()
        result = sb.table("api_users") \
            .select("plan_tier") \
            .eq("api_key_hash", key_hash) \
            .maybe_single() \
            .execute()
        if result.data:
            return result.data["plan_tier"]
        return "free"
    except Exception as exc:
        logger.warning("rate_limiter.get_plan_tier: Supabase error — defaulting to free: %s", exc)
        return "free"


def set_plan_tier(api_key: str, tier: str) -> None:
    """
    Upgrade or downgrade a key's plan tier.
    Called by Gumroad webhook handler when payment is confirmed.
    tier must be one of: 'free', 'paid', 'enterprise'
    """
    valid_tiers = {"free", "paid", "enterprise"}
    if tier not in valid_tiers:
        raise ValueError(f"Invalid tier '{tier}'. Must be one of: {valid_tiers}")

    key_hash = _hash_key(api_key)
    try:
        sb = _get_supabase()
        # Upsert — creates row if not exists
        sb.table("api_users").upsert({
            "api_key_hash": key_hash,
            "plan_tier":    tier,
            "daily_count":  0,
            "reset_date":   _today_utc(),
        }, on_conflict="api_key_hash").execute()
        logger.info("rate_limiter: set tier=%s for hash prefix %s", tier, key_hash[:8])
    except Exception as exc:
        logger.error("rate_limiter.set_plan_tier failed: %s", exc)
        raise


# ---------------------------------------------------------------------------
# Internal helper
# ---------------------------------------------------------------------------

def _reset_or_increment(sb, key_hash: str, new_count: int,
                        stored_date: str, today: str) -> None:
    if stored_date != today:
        sb.table("api_users") \
            .update({"daily_count": 1, "reset_date": today}) \
            .eq("api_key_hash", key_hash) \
            .execute()
    else:
        sb.table("api_users") \
            .update({"daily_count": new_count}) \
            .eq("api_key_hash", key_hash) \
            .execute()
