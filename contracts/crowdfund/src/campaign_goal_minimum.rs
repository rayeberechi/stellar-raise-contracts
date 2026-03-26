//! # campaign_goal_minimum
//!
//! @title   CampaignGoalMinimum — Enforces minimum campaign goal thresholds.
//!
//! @notice  This module provides all validation helpers for campaign creation
//!          parameters: goal amount, minimum contribution, deadline, and
//!          platform fee. It also exposes a progress-in-basis-points helper
//!          used by the frontend and indexers.
//!
//! @dev     All validators are `#[inline]` pure functions with no side-effects.
//!          They are called inside `initialize()` before any storage writes so
//!          that a rejected parameter leaves no partial ledger state.
//!
//! ## Security rationale
//!
//! | Threat | Mitigation |
//! |--------|-----------|
//! | Zero-goal drain | `MIN_GOAL_AMOUNT = 1` rejects goals that would make a campaign immediately "successful" |
//! | Ledger spam | Non-zero minimum prevents dust campaigns that waste storage |
//! | Negative goal | `i128` comparison rejects all values < 1 in a single branch |
//! | Fee overflow | `MAX_PLATFORM_FEE_BPS = 10_000` caps fee at 100% |
//! | Deadline bypass | `MIN_DEADLINE_OFFSET` ensures campaigns run for at least 60 s |
//! | Progress overflow | `compute_progress_bps` uses `saturating_mul` and caps at `MAX_PROGRESS_BPS` |

// ── Constants ────────────────────────────────────────────────────────────────

/// @notice Minimum allowed campaign goal in token units.
///
/// @dev    Set to 1 so that any non-zero, non-negative goal is accepted in
///         test and development environments. Governance can raise this value
///         via a contract upgrade (see docs/campaign_goal_minimum.md).
///
/// @custom:security A goal of 0 would make a campaign immediately "successful"
///         after any contribution, allowing the creator to drain funds with no
///         real commitment. This constant closes that attack surface.
pub const MIN_GOAL_AMOUNT: i128 = 1;

/// @notice Minimum allowed `min_contribution` value in token units.
///
/// @dev    Prevents contributions of 0 tokens, which would allow an attacker
///         to register as a contributor without transferring any value.
pub const MIN_CONTRIBUTION_AMOUNT: i128 = 1;

/// @notice Maximum allowed platform fee in basis points (100% = 10_000 bps).
///
/// @custom:security Any fee_bps above this value is a configuration error.
///         The assertion in `validate_platform_fee` acts as a last-line-of-
///         defence guard even if upstream validation is bypassed.
pub const MAX_PLATFORM_FEE_BPS: u32 = 10_000;

/// @notice Scale factor used when computing progress in basis points.
///
/// @dev    `progress_bps = (total_raised * PROGRESS_BPS_SCALE) / goal`.
///         Must equal `MAX_PROGRESS_BPS` so that a fully-met goal produces
///         exactly `MAX_PROGRESS_BPS`.
pub const PROGRESS_BPS_SCALE: i128 = 10_000;

/// @notice Maximum value returned by `compute_progress_bps`.
///
/// @dev    Progress is capped at this value even when `total_raised > goal`
///         (over-funded campaigns). Equals `PROGRESS_BPS_SCALE`.
pub const MAX_PROGRESS_BPS: u32 = 10_000;

/// @notice Minimum number of seconds a campaign deadline must be in the future
///         relative to the current ledger timestamp.
///
/// @dev    Prevents campaigns with deadlines so close to `now` that no
///         contributor could realistically participate before the deadline
///         passes.
pub const MIN_DEADLINE_OFFSET: u64 = 60;

// ── Validation helpers ───────────────────────────────────────────────────────

/// @notice Validates that `goal` meets the minimum threshold.
///
/// @dev    Returns `&'static str` rather than `ContractError` so this helper
///         can be used in off-chain tooling without pulling in the full
///         contract dependency.
///
/// @param  goal  The proposed campaign goal in token units.
/// @return       `Ok(())` if `goal >= MIN_GOAL_AMOUNT`, `Err` with a reason
///               string otherwise.
///
/// @custom:security The comparison is a single signed integer operation —
///         no arithmetic is performed, so integer overflow is impossible.
#[inline]
pub fn validate_goal(goal: i128) -> Result<(), &'static str> {
    if goal < MIN_GOAL_AMOUNT {
        return Err("goal must be at least MIN_GOAL_AMOUNT");
    }
    Ok(())
}

/// @notice Validates that `goal_amount` meets the minimum threshold, returning
///         a typed `ContractError::GoalTooLow` on failure.
///
/// @notice This is the on-chain enforcement entry point. Call this inside
///         `initialize()` before persisting any campaign state so that a
///         below-threshold goal is rejected atomically with no side-effects.
///
/// @dev    The `_env` parameter is accepted for API consistency with other
///         Soroban validation helpers and to allow future ledger-aware
///         threshold logic (e.g. governance-controlled minimums stored in
///         contract storage) without a breaking signature change.
///
/// @param  _env         The Soroban environment (reserved for future use).
/// @param  goal_amount  The proposed campaign goal in token units.
/// @return              `Ok(())` if `goal_amount >= MIN_GOAL_AMOUNT`,
///                      `Err(ContractError::GoalTooLow)` otherwise.
///
/// @custom:security Integer-overflow safety: the comparison is a single signed
///         integer operation — no arithmetic is performed.
#[inline]
pub fn validate_goal_amount(
    _env: &soroban_sdk::Env,
    goal_amount: i128,
) -> Result<(), crate::ContractError> {
    if goal_amount < MIN_GOAL_AMOUNT {
        return Err(crate::ContractError::GoalTooLow);
    }
    Ok(())
}

/// @notice Validates that `min_contribution` meets the minimum floor.
///
/// @param  min_contribution  The proposed minimum contribution in token units.
/// @return                   `Ok(())` if valid, `Err` with a reason string
///                           otherwise.
///
/// @custom:security A `min_contribution` of 0 would allow an attacker to
///         register as a contributor without transferring any value, polluting
///         the contributor list and potentially triggering NFT mints for free.
#[inline]
pub fn validate_min_contribution(min_contribution: i128) -> Result<(), &'static str> {
    if min_contribution < MIN_CONTRIBUTION_AMOUNT {
        return Err("min_contribution must be at least MIN_CONTRIBUTION_AMOUNT");
    }
    Ok(())
}

/// @notice Validates that `deadline` is sufficiently far in the future.
///
/// @param  now       Current ledger timestamp (seconds since Unix epoch).
/// @param  deadline  Proposed campaign deadline (seconds since Unix epoch).
/// @return           `Ok(())` if `deadline >= now + MIN_DEADLINE_OFFSET`,
///                   `Err` with a reason string otherwise.
///
/// @custom:security Uses `saturating_add` to prevent overflow when `now` is
///         near `u64::MAX`. A saturated sum of `u64::MAX` means any finite
///         deadline will be rejected, which is the safe default.
#[inline]
pub fn validate_deadline(now: u64, deadline: u64) -> Result<(), &'static str> {
    let min_deadline = now.saturating_add(MIN_DEADLINE_OFFSET);
    if deadline < min_deadline {
        return Err("deadline must be at least MIN_DEADLINE_OFFSET seconds in the future");
    }
    Ok(())
}

/// @notice Validates that `fee_bps` does not exceed `MAX_PLATFORM_FEE_BPS`.
///
/// @param  fee_bps  Platform fee in basis points (0 = no fee, 10_000 = 100%).
/// @return          `Ok(())` if `fee_bps <= MAX_PLATFORM_FEE_BPS`, `Err`
///                  with a reason string otherwise.
///
/// @custom:security A fee above 100% would cause the fee transfer to exceed
///         the total raised, resulting in an underflow panic or incorrect
///         creator payout. This guard prevents that at the validation layer.
#[inline]
pub fn validate_platform_fee(fee_bps: u32) -> Result<(), &'static str> {
    if fee_bps > MAX_PLATFORM_FEE_BPS {
        return Err("fee_bps must not exceed MAX_PLATFORM_FEE_BPS");
    }
    Ok(())
}

/// @notice Computes campaign funding progress in basis points.
///
/// @dev    `progress_bps = (total_raised * PROGRESS_BPS_SCALE) / goal`.
///         Result is capped at `MAX_PROGRESS_BPS` for over-funded campaigns.
///         Returns 0 when `goal <= 0` to avoid division by zero.
///
/// @param  total_raised  Total tokens raised so far.
/// @param  goal          Campaign funding goal.
/// @return               Progress in basis points, capped at `MAX_PROGRESS_BPS`.
///
/// @custom:security Uses `saturating_mul` to prevent overflow on very large
///         `total_raised` values. The cap ensures the return value is always
///         in `[0, MAX_PROGRESS_BPS]`.
#[inline]
pub fn compute_progress_bps(total_raised: i128, goal: i128) -> u32 {
    if goal <= 0 {
        return 0;
    }
    let raw = total_raised.saturating_mul(PROGRESS_BPS_SCALE) / goal;
    if raw >= PROGRESS_BPS_SCALE {
        return MAX_PROGRESS_BPS;
    }
    raw.max(0) as u32
}
