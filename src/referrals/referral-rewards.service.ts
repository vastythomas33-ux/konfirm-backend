import { Injectable, Logger } from '@nestjs/common';
import { Cron } from '@nestjs/schedule';
import { pool } from '../db/pool';

// ---------------------------------------------------------------------------
// Referral reward constants
//
// These are the levers that prevent the referral system from becoming a
// self-serve, indefinitely-renewable fee-discount lever.  Every value here
// has a rationale; change any of them only after updating the comment.
// ---------------------------------------------------------------------------

// A referred merchant must have processed at least this many USDC before the
// referrer earns anything.  A dust payment (0.0000001 USDC) used to be
// enough — that made the reward farmable for essentially zero cost on
// Stellar's near-free network.  $1 USD is still trivially low for a real
// business but high enough that the Stellar base reserve + a typical testnet
// fund cycle no longer covers it from pocket change, and it forces at least
// one real checkout interaction rather than a self-constructed operation.
const MIN_REFERRAL_QUALIFYING_AMOUNT_USDC = 1;

// How much of a per-payment volume discount the referrer's promo covers.
// A NULL cap (the old behaviour) meant unlimited volume at the discounted
// rate forever — that's a revenue leak at any meaningful merchant scale.
// $500 matches the referred merchant's own onboarding trial cap, so the
// reward stays proportional: one referral → one trial's worth of fee savings,
// not a permanent discount.
const REWARD_VOLUME_CAP_USDC = 500;

// Base length of a single referral reward, in days.  Each subsequent reward
// earned by the same referrer extends from wherever the current expiry is
// (so rewards stack, not reset), using a diminishing-returns divisor (see
// REWARD_DISCOUNT_DIVISOR below).
const REWARD_DAYS = 30;

// First reward gives the referrer base_fee / 2 (50 % off).
// Each successive reward reduces the discount further:
//   reward 1 → fee_bps / 2   (50 % off)
//   reward 2 → fee_bps / 3   (~33 % off)
//   reward 3 → fee_bps / 4   (25 % off)
//   reward N → fee_bps / (N + 1)
// This prevents indefinite farming: each extra sock-puppet account yields
// a smaller marginal gain, and after a handful of referrals the effective
// discount converges to base rate.  The first divisor value is 2 (for a
// referrer who has 0 prior rewards) — computed at grant time from
// referrer_reward_count, not stored here.
//
// Works on the referrer's CURRENT fee_bps, not a fixed absolute, so a
// negotiated enterprise rate stays proportional rather than accidentally
// being overridden by a generic formula.
const BASE_REWARD_DIVISOR_OFFSET = 2; // divisor = reward_count + BASE_REWARD_DIVISOR_OFFSET

// Hard cap on total rewards a single referrer_id can ever earn.  Without
// this, an attacker could automate signups and drive the effective fee toward
// zero via the diminishing-but-never-zero formula above.  5 caps the maximum
// discount at base_fee / 7 (~14 % of base) and limits the attack surface to
// 5 sock-puppet accounts maximum per referrer, each requiring a $1+ payment.
// Enforced atomically in the DB via UPDATE … WHERE referrer_reward_count < $n
// rather than a read-then-write, so two overlapping sweep processes cannot
// both grant a 6th reward to the same referrer.
const MAX_REFERRAL_REWARDS_PER_REFERRER = 5;

// Triggers only on the referred merchant's real activation (a genuine paid
// payment above MIN_REFERRAL_QUALIFYING_AMOUNT_USDC), never on mere signup
// — gating the reward on this is what makes referral-farming via empty
// signups pointless.  In-process @Cron(), same reasoning as
// ChannelKeeperService (x402/channel-keeper.service.ts): this is small,
// tightly coupled to the same Postgres pool the api service already owns,
// and a separate service would just reproduce the backup-cron
// shared-railway.json class of bug for no real benefit.
@Injectable()
export class ReferralRewardsService {
  private readonly logger = new Logger(ReferralRewardsService.name);

  @Cron('*/5 * * * *')
  async sweep(): Promise<void> {
    try {
      // Step 1 — Atomic claim.
      //
      // Only a referral row that:
      //   (a) hasn't had its reward granted yet (reward_granted_at IS NULL), AND
      //   (b) has at least one paid payment >= MIN_REFERRAL_QUALIFYING_AMOUNT_USDC
      //       on the referred merchant's account
      // gets claimed.  The UPDATE…RETURNING makes "claim it" and "read whether
      // I actually won the race" the same operation — two overlapping sweeps
      // can never both grant the same referral's reward twice.
      const { rows: claimed } = await pool.query<{ id: string; referrer_id: string }>(
        `WITH activated AS (
           SELECT r.id, r.referrer_id
           FROM referrals r
           WHERE r.reward_granted_at IS NULL
             AND EXISTS (
               SELECT 1 FROM payments p
               WHERE p.merchant_id = r.referred_id
                 AND p.status = 'paid'
                 AND p.amount_usdc >= $1
             )
         )
         UPDATE referrals
         SET reward_granted_at = NOW()
         WHERE id IN (SELECT id FROM activated)
         RETURNING id, referrer_id`,
        [MIN_REFERRAL_QUALIFYING_AMOUNT_USDC],
      );

      for (const { id, referrer_id: referrerId } of claimed) {
        await this.grantReward(referrerId, id);
      }
    } catch (err) {
      this.logger.error(`referral rewards sweep failed: ${err}`);
    }
  }

  private async grantReward(referrerId: string, referralId: string): Promise<void> {
    // Step 2 — Atomic cap + increment.
    //
    // The UPDATE only fires when referrer_reward_count < MAX, so the cap
    // check and the increment are one operation.  RETURNING tells us whether
    // we actually wrote a row (count was under the cap) or the cap was
    // already reached (no row returned).  This is safe across concurrent
    // sweep processes — no read-then-write race.
    //
    // We also read fee_bps and the current promo_expires_at here so we can
    // compute the new discount and extend (not reset) the expiry in a single
    // subsequent write.
    const { rows: capRows } = await pool.query<{
      fee_bps: number;
      new_count: number;
      current_expires_at: Date | null;
    }>(
      `UPDATE merchants
       SET referrer_reward_count = referrer_reward_count + 1
       WHERE id = $1
         AND referrer_reward_count < $2
       RETURNING fee_bps,
                 referrer_reward_count AS new_count,
                 promo_expires_at      AS current_expires_at`,
      [referrerId, MAX_REFERRAL_REWARDS_PER_REFERRER],
    );

    if (capRows.length === 0) {
      // Cap already reached for this referrer — log and move on.  The
      // referral row was already marked reward_granted_at = NOW() above, so
      // this won't be retried.  The referred merchant still keeps their own
      // onboarding trial discount; only the referrer's bonus is withheld.
      this.logger.warn(
        `referrer ${referrerId} has reached the cap of ${MAX_REFERRAL_REWARDS_PER_REFERRER} rewards; ` +
          `referral ${referralId} not rewarded`,
      );
      return;
    }

    const { fee_bps: feeBps, new_count: newCount, current_expires_at: currentExpiresAt } = capRows[0];

    // Step 3 — Compute the discounted rate with diminishing returns.
    //
    // new_count is the count AFTER the increment, so:
    //   first reward  (new_count=1) → divisor = 1 + 2 = 3? No —
    // We want: 1st reward → /2, 2nd → /3, Nth → /(N+1).
    // new_count is already 1-indexed (1 = first reward), so:
    //   divisor = new_count + (BASE_REWARD_DIVISOR_OFFSET - 1) = new_count + 1
    const divisor = newCount + (BASE_REWARD_DIVISOR_OFFSET - 1);
    const newPromoFeeBps = Math.max(Math.floor(feeBps / divisor), 1);

    // Step 4 — Stack (extend) the reward rather than reset it, unless a
    // more favorable active promo is already in place.
    //
    // GREATEST(NOW(), promo_expires_at) means:
    //   - If an existing promo is still active and isn't more favorable,
    //     we extend from its end date.
    //   - If it's expired (or there was never one), we start from now.
    // This prevents "renewal farming" where an attacker fires a new referral
    // right before the previous one expires and ends up with a perpetual
    // promo.  Each new reward adds REWARD_DAYS on top of however much time
    // was already banked — effectively the same time as a fresh grant, but
    // no earlier than the natural expiry, so the maximum outstanding discount
    // at any moment is one REWARD_DAYS window, not N stacked ones.
    //
    // promo_volume_cap_usdc is now non-NULL (REWARD_VOLUME_CAP_USDC), capping
    // the reward to $500 of discounted volume, matching the referred
    // merchant's own onboarding trial.  NULL was the old behaviour —
    // explicitly uncapped — which made the reward a permanent unlimited
    // discount at any volume. Existing promos with a lower fee, or an equal
    // fee and at least as much volume, are preserved instead of replaced.
    const { rows: promoRows } = await pool.query(
      `UPDATE merchants
       SET promo_fee_bps       = $2,
           promo_expires_at    = GREATEST(NOW(), COALESCE(promo_expires_at, NOW()))
                                 + ($3 * INTERVAL '24 hours'),
           promo_volume_cap_usdc = $4
       WHERE id = $1
         AND NOT (
           promo_expires_at > NOW()
           AND promo_fee_bps IS NOT NULL
           AND (
             promo_fee_bps < $2
             OR (promo_fee_bps = $2 AND (promo_volume_cap_usdc IS NULL OR promo_volume_cap_usdc >= $4))
           )
         )
       RETURNING promo_fee_bps`,
      [referrerId, newPromoFeeBps, REWARD_DAYS, REWARD_VOLUME_CAP_USDC],
    );

    if (promoRows.length === 0) {
      this.logger.log(`kept the more favorable active promo for merchant ${referrerId}`);
      return;
    }

    this.logger.log(
      `granted referrer reward to merchant ${referrerId} for referral ${referralId}: ` +
        `promo_fee_bps=${newPromoFeeBps} (divisor=${divisor}, reward #${newCount}), ` +
        `+${REWARD_DAYS}d, vol_cap=${REWARD_VOLUME_CAP_USDC} USDC`,
    );
  }
}
