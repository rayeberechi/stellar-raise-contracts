# Campaign Goal Minimum Threshold Enforcement — Security Refactor

## Overview

The `campaign_goal_minimum` module enforces minimum thresholds for all campaign
creation parameters: goal amount, minimum contribution, deadline, and platform
fee. It also provides a progress-in-basis-points helper used by the frontend
and off-chain indexers.

This refactor fixes a broken source file (duplicate functions, incomplete
`create_campaign` stub, mismatched types) and consolidates all threshold
validation into clean, independently testable, `#[inline]` pure functions.

---

## Security Rationale

| Threat | Mitigation |
|--------|-----------|
| Zero-goal drain | `MIN_GOAL_AMOUNT = 1` rejects goals that make a campaign immediately "successful" after any contribution |
| Ledger spam | Non-zero minimum prevents dust campaigns that waste storage |
| Negative goal | Single `i128` comparison rejects all values < 1 without a separate branch |
| Fee overflow | `MAX_PLATFORM_FEE_BPS = 10_000` caps fee at 100% — above this, fee transfer would exceed total raised |
| Deadline bypass | `MIN_DEADLINE_OFFSET = 60s` ensures campaigns run long enough for contributors to participate |
| Progress overflow | `compute_progress_bps` uses `saturating_mul` and caps at `MAX_PROGRESS_BPS` |
| Division by zero | `compute_progress_bps` returns 0 when `goal <= 0` |

---

## Constants

| Constant | Value | Purpose |
|----------|-------|---------|
| `MIN_GOAL_AMOUNT` | `1i128` | Minimum campaign goal in token units |
| `MIN_CONTRIBUTION_AMOUNT` | `1i128` | Minimum `min_contribution` value |
| `MAX_PLATFORM_FEE_BPS` | `10_000u32` | Maximum platform fee (100%) |
| `PROGRESS_BPS_SCALE` | `10_000i128` | Scale factor for progress calculation |
| `MAX_PROGRESS_BPS` | `10_000u32` | Maximum progress value (= 100%) |
| `MIN_DEADLINE_OFFSET` | `60u64` | Minimum seconds deadline must be in the future |

---

## API Reference

### `validate_goal(goal: i128) -> Result<(), &'static str>`

Off-chain / tooling helper. Returns a descriptive string error to avoid
pulling in `ContractError`.

### `validate_goal_amount(_env: &Env, goal_amount: i128) -> Result<(), ContractError>`

On-chain enforcement entry point. Returns `ContractError::GoalTooLow` when
`goal_amount < MIN_GOAL_AMOUNT`. The `_env` parameter is reserved for future
governance-controlled thresholds stored in contract storage.

### `validate_min_contribution(min_contribution: i128) -> Result<(), &'static str>`

Rejects `min_contribution < MIN_CONTRIBUTION_AMOUNT`.

### `validate_deadline(now: u64, deadline: u64) -> Result<(), &'static str>`

Rejects deadlines less than `now + MIN_DEADLINE_OFFSET`. Uses `saturating_add`
to prevent overflow when `now` is near `u64::MAX`.

### `validate_platform_fee(fee_bps: u32) -> Result<(), &'static str>`

Rejects `fee_bps > MAX_PLATFORM_FEE_BPS`.

### `compute_progress_bps(total_raised: i128, goal: i128) -> u32`

Returns `(total_raised * 10_000) / goal`, capped at `MAX_PROGRESS_BPS`.
Returns 0 when `goal <= 0`.

---

## Integration

Call `validate_goal_amount` inside `initialize()` before any storage writes:

```rust
use crate::campaign_goal_minimum::validate_goal_amount;

pub fn initialize(env: Env, goal: i128, ...) -> Result<(), ContractError> {
    validate_goal_amount(&env, goal)?;
    // ... rest of initialization
    Ok(())
}
```

---

## Security Assumptions

- **Atomic rejection** — validators are called before any `env.storage()` writes.
- **No integer overflow** — all validators use comparisons only; `compute_progress_bps` uses `saturating_mul`.
- **Upgrade safety** — raising `MIN_GOAL_AMOUNT` in a new binary only affects new `initialize()` calls.
- **Governance extension** — `validate_goal_amount` accepts `&Env` for future on-chain threshold storage.
