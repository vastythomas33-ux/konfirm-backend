import { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import * as bcrypt from 'bcryptjs';
import cookieParser from 'cookie-parser';
import request from 'supertest';
import { AppModule } from '../src/app.module';
import { pool } from '../src/db/pool';
import { ReferralRewardsService } from '../src/referrals/referral-rewards.service';
import { WithdrawalsService } from '../src/withdrawals/withdrawals.service';

// The point of this feature: an admin can suspend a merchant and have it
// actually take effect immediately — not just on the merchant's next login,
// but against a session cookie that was already issued before the
// suspension happened. Same real-Postgres, no-mocks approach as
// critical-path.e2e-spec.ts.
describe('admin workflow: suspend/reactivate a merchant (e2e)', () => {
  let app: INestApplication;
  const adminEmail = `admin-e2e-${Date.now()}@example.com`;
  const merchantEmail = `merchant-e2e-${Date.now()}@example.com`;
  const stellarAddress = 'GBXBABMFZIJPTOFI6STUXA2FMEXDBB4URBD3VS5XDHKMFHGLJZ5WPQBB';
  let adminCookie: string;
  let merchantCookie: string;
  let merchantId: string;
  let linkId: string;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] }).compile();
    app = moduleRef.createNestApplication();
    app.use(cookieParser());
    await app.init();

    const passwordHash = await bcrypt.hash('an-admin-password-000', 10);
    await pool.query('INSERT INTO admins (email, password_hash, name) VALUES ($1, $2, $3)', [adminEmail, passwordHash, 'E2E Admin']);
  });

  afterAll(async () => {
    // Children before parents — withdrawal_attempts/payments/links all
    // reference merchants; blocked_addresses/admin_actions reference admins.
    await pool.query('DELETE FROM withdrawal_attempts WHERE merchant_id = (SELECT id FROM merchants WHERE email = $1)', [merchantEmail]);
    await pool.query('DELETE FROM payments WHERE merchant_id = (SELECT id FROM merchants WHERE email = $1)', [merchantEmail]);
    await pool.query('DELETE FROM links WHERE merchant_id = (SELECT id FROM merchants WHERE email = $1)', [merchantEmail]);
    await pool.query('DELETE FROM blocked_addresses WHERE blocked_by IN (SELECT id FROM admins WHERE email = $1)', [adminEmail]);
    await pool.query('DELETE FROM admin_actions WHERE admin_id IN (SELECT id FROM admins WHERE email = $1)', [adminEmail]);
    await pool.query('DELETE FROM admins WHERE email = $1', [adminEmail]);
    await pool.query('DELETE FROM merchants WHERE email = $1', [merchantEmail]);
    await app.close();
    await pool.end();
  });

  it('logs the admin in on a distinct cookie from the merchant session', async () => {
    const res = await request(app.getHttpServer())
      .post('/admin/auth/login')
      .send({ email: adminEmail, password: 'an-admin-password-000' })
      .expect(200);

    const rawCookie = res.headers['set-cookie']?.[0];
    expect(rawCookie).toContain('konfirm_admin_session=');
    adminCookie = rawCookie.split(';')[0];
  });

  it('GET /admin/auth/me returns the current admin with a valid session', async () => {
    const res = await request(app.getHttpServer()).get('/admin/auth/me').set('Cookie', adminCookie).expect(200);
    expect(res.body.admin).toBeDefined();
    expect(res.body.admin.email).toBe(adminEmail);
    expect(res.body.admin.name).toBe('E2E Admin');
    expect(res.body.admin.id).toEqual(expect.any(String));
  });

  it('GET /admin/auth/me rejects without a valid session', async () => {
    await request(app.getHttpServer()).get('/admin/auth/me').expect(401);
  });

  it('POST /admin/auth/logout clears the session cookie and invalidates the token', async () => {
    // Logout
    const logoutRes = await request(app.getHttpServer())
      .post('/admin/auth/logout')
      .set('Cookie', adminCookie)
      .expect(200);
    expect(logoutRes.body.ok).toBe(true);

    // The cookie should be cleared (Set-Cookie header with max-age=0 or similar)
    const setCookieHeader = logoutRes.headers['set-cookie'];
    expect(setCookieHeader).toBeDefined();

    // Attempting to use the old cookie should now fail
    await request(app.getHttpServer()).get('/admin/auth/me').set('Cookie', adminCookie).expect(401);
  });

  it('POST /admin/auth/logout without a cookie is a no-op', async () => {
    // Should not error, just succeed silently
    const res = await request(app.getHttpServer()).post('/admin/auth/logout').expect(200);
    expect(res.body.ok).toBe(true);
  });

  it('rejects a merchant-facing route with the admin cookie', async () => {
    await request(app.getHttpServer()).get('/auth/me').set('Cookie', adminCookie).expect(401);
  });

  it('signs up a merchant and creates a payable link', async () => {
    const signupRes = await request(app.getHttpServer())
      .post('/auth/signup')
      .send({ email: merchantEmail, password: 'a-real-password-000', name: 'E2E Merchant', stellar_base_address: stellarAddress })
      .expect(201);
    merchantId = signupRes.body.merchant.id;
    merchantCookie = signupRes.headers['set-cookie'][0].split(';')[0];

    const linkRes = await request(app.getHttpServer())
      .post('/links')
      .set('Cookie', merchantCookie)
      .send({ amount_usdc: '5.00', currency: 'XLM', description: 'e2e admin test link' })
      .expect(201);
    linkId = linkRes.body.id;
  });

  it('returns real aggregate stats, not fabricated ones', async () => {
    const res = await request(app.getHttpServer()).get('/admin/stats').set('Cookie', adminCookie).expect(200);
    expect(res.body.merchants.total).toBeGreaterThanOrEqual(1);
    expect(res.body.merchants.active + res.body.merchants.suspended + res.body.merchants.pending).toBe(res.body.merchants.total);
    // Always exactly 7 entries, zero-filled for days with no payments —
    // never a partial or ragged series for the chart to choke on.
    expect(res.body.daily_volume).toHaveLength(7);
    expect(res.body.daily_volume[6].date).toBe(new Date().toISOString().slice(0, 10));
    expect(res.body.compliance.blocked_count).toBeGreaterThanOrEqual(0);
    expect(res.body.withdrawals.open_count).toBeGreaterThanOrEqual(0);
  });

  it('lists the merchant via the admin API', async () => {
    const res = await request(app.getHttpServer()).get('/admin/merchants').set('Cookie', adminCookie).expect(200);
    expect(res.body.some((m: { email: string }) => m.email === merchantEmail)).toBe(true);
  });

  it('rejects the admin API with no admin session at all', async () => {
    await request(app.getHttpServer()).get('/admin/merchants').expect(401);
  });

  it('suspends the merchant, which instantly invalidates their existing session cookie', async () => {
    await request(app.getHttpServer())
      .patch(`/admin/merchants/${merchantId}/status`)
      .set('Cookie', adminCookie)
      .send({ status: 'suspended', reason: 'e2e test' })
      .expect(200);

    // Same cookie as before — never re-issued — now rejected.
    await request(app.getHttpServer()).get('/auth/me').set('Cookie', merchantCookie).expect(401);
  });

  it("rejects checkout on the suspended merchant's link", async () => {
    const res = await request(app.getHttpServer())
      .get('/payments/prepare-tx')
      .query({ linkId, muxed_id: '555555555', payer: 'GDIET4T37N35XU4FY52RMR4Z653WYFITEHGIJXN4VEQTDYR5JSURJDPL' })
      .expect(400);
    expect(res.body.message).toMatch(/not currently accepting payments/);
  });

  it('logs the suspend action to the audit trail', async () => {
    const res = await request(app.getHttpServer()).get('/admin/activity').set('Cookie', adminCookie).expect(200);
    const entry = res.body.find((a: { target_id: string }) => a.target_id === merchantId);
    expect(entry).toBeDefined();
    expect(entry.action).toBe('merchant.suspend');
  });

  it('reactivating the merchant restores both login and checkout', async () => {
    await request(app.getHttpServer())
      .patch(`/admin/merchants/${merchantId}/status`)
      .set('Cookie', adminCookie)
      .send({ status: 'active' })
      .expect(200);

    const loginRes = await request(app.getHttpServer())
      .post('/auth/login')
      .send({ email: merchantEmail, password: 'a-real-password-000' })
      .expect(200);
    const freshCookie = loginRes.headers['set-cookie'][0].split(';')[0];
    await request(app.getHttpServer()).get('/auth/me').set('Cookie', freshCookie).expect(200);

    await request(app.getHttpServer())
      .get('/payments/prepare-tx')
      .query({ linkId, muxed_id: '666666666', payer: 'GDIET4T37N35XU4FY52RMR4Z653WYFITEHGIJXN4VEQTDYR5JSURJDPL' })
      .expect(200);
  });

  describe('compliance: blocking an address takes precedence over the on-chain check', () => {
    const payer = 'GDIET4T37N35XU4FY52RMR4Z653WYFITEHGIJXN4VEQTDYR5JSURJDPL';
    let blockedId: string;

    it('blocks the address, which rejects checkout instantly (no chain call needed)', async () => {
      const res = await request(app.getHttpServer())
        .post('/admin/compliance/blocked-addresses')
        .set('Cookie', adminCookie)
        .send({ stellar_address: payer, reason: 'e2e compliance test' })
        .expect(201);
      blockedId = res.body.id;

      const prepRes = await request(app.getHttpServer())
        .get('/payments/prepare-tx')
        .query({ linkId, muxed_id: '777777777', payer })
        .expect(403);
      expect(prepRes.body.message).toMatch(/not permitted to pay/);
    });

    it('rejects a duplicate block with a real conflict, not a silent success', async () => {
      await request(app.getHttpServer())
        .post('/admin/compliance/blocked-addresses')
        .set('Cookie', adminCookie)
        .send({ stellar_address: payer })
        .expect(409);
    });

    it('unblocking restores checkout', async () => {
      await request(app.getHttpServer())
        .delete(`/admin/compliance/blocked-addresses/${blockedId}`)
        .set('Cookie', adminCookie)
        .expect(200);

      await request(app.getHttpServer())
        .get('/payments/prepare-tx')
        .query({ linkId, muxed_id: '888888888', payer })
        .expect(200);
    });
  });

  describe('payments: admin can review and change status', () => {
    let paymentId: string;

    beforeAll(async () => {
      // prepare-tx never creates a payments row (only the reconciler does,
      // after Horizon confirms a real signed transaction) — this e2e run
      // has no private key to sign with, so a row is inserted directly to
      // exercise the admin review endpoints against something real.
      const { rows } = await pool.query(
        `INSERT INTO payments (merchant_id, muxed_id, muxed_address, payer_address, asset_code, amount_usdc, net_usdc, paging_token, tx_hash, ledger_sequence)
         VALUES ($1, 999, 'M...e2e', $2, 'XLM', 5, 5, $3, 'e2e-tx-hash', 1)
         RETURNING id`,
        [merchantId, 'GDIET4T37N35XU4FY52RMR4Z653WYFITEHGIJXN4VEQTDYR5JSURJDPL', `e2e-paging-token-${Date.now()}`],
      );
      paymentId = rows[0].id;
    });

    it('lists it via the admin API', async () => {
      const res = await request(app.getHttpServer()).get('/admin/payments').set('Cookie', adminCookie).expect(200);
      expect(res.body.some((p: { id: string }) => p.id === paymentId)).toBe(true);
    });

    it('holds it, then releases it back to paid', async () => {
      const heldRes = await request(app.getHttpServer())
        .patch(`/admin/payments/${paymentId}/status`)
        .set('Cookie', adminCookie)
        .send({ status: 'held', reason: 'e2e review' })
        .expect(200);
      expect(heldRes.body.status).toBe('held');

      const filtered = await request(app.getHttpServer())
        .get('/admin/payments')
        .query({ status: 'held' })
        .set('Cookie', adminCookie)
        .expect(200);
      expect(filtered.body.some((p: { id: string }) => p.id === paymentId)).toBe(true);

      const paidRes = await request(app.getHttpServer())
        .patch(`/admin/payments/${paymentId}/status`)
        .set('Cookie', adminCookie)
        .send({ status: 'paid' })
        .expect(200);
      expect(paidRes.body.status).toBe('paid');
    });
  });

  describe('fee revenue, users, and wallets: aggregations over existing payment data', () => {
    // A fresh, never-reused payer address so payment_count/total_volume
    // assertions aren't polluted by payments other describe blocks in this
    // file insert against the shared e2e payer address.
    const feWPayer = `G${'FEEUSERSWALLETS'.padEnd(55, 'A')}`;
    let baselineFeeSummary: { payment_count: number; total_fee_usdc: string };
    let blockedId: string;

    beforeAll(async () => {
      const before = await request(app.getHttpServer()).get('/admin/fee-revenue/summary').set('Cookie', adminCookie).expect(200);
      baselineFeeSummary = before.body;

      // One paid (fee counts), one refunded (fee must NOT count) — proves
      // the summary is filtering on status, not just summing every row.
      await pool.query(
        `INSERT INTO payments (merchant_id, muxed_id, muxed_address, payer_address, asset_code, amount_usdc, fee_usdc, net_usdc, status, paging_token, tx_hash, ledger_sequence)
         VALUES
           ($1, 111, 'M...fw1', $2, 'XLM', 10, 1, 9, 'paid', $3, 'e2e-fw-tx-1', 1),
           ($1, 112, 'M...fw2', $2, 'XLM', 20, 2, 18, 'refunded', $4, 'e2e-fw-tx-2', 1)`,
        [merchantId, feWPayer, `e2e-fw-paging-1-${Date.now()}`, `e2e-fw-paging-2-${Date.now()}`],
      );
    });

    afterAll(async () => {
      await pool.query('DELETE FROM payments WHERE payer_address = $1', [feWPayer]);
      if (blockedId) await pool.query('DELETE FROM blocked_addresses WHERE id = $1', [blockedId]);
    });

    it('fee revenue summary counts only the paid payment\'s fee, not the refunded one', async () => {
      const res = await request(app.getHttpServer()).get('/admin/fee-revenue/summary').set('Cookie', adminCookie).expect(200);
      expect(res.body.payment_count).toBe(baselineFeeSummary.payment_count + 1);
      expect(Number(res.body.total_fee_usdc) - Number(baselineFeeSummary.total_fee_usdc)).toBeCloseTo(1, 5);
    });

    it('users lists the payer with both payments counted (paid AND refunded — this is activity history, not revenue)', async () => {
      const res = await request(app.getHttpServer()).get('/admin/users').set('Cookie', adminCookie).expect(200);
      const row = res.body.find((u: { payer_address: string }) => u.payer_address === feWPayer);
      expect(row).toBeDefined();
      expect(Number(row.payment_count)).toBe(2);
      expect(Number(row.total_volume_usdc)).toBeCloseTo(30, 5);
      expect(Number(row.refunded_count)).toBe(1);
    });

    it('wallets shows the payer role, then also shows blocked once the same address is blocked', async () => {
      const before = await request(app.getHttpServer()).get('/admin/wallets').set('Cookie', adminCookie).expect(200);
      const beforeRow = before.body.find((w: { address: string }) => w.address === feWPayer);
      expect(beforeRow.roles).toEqual(['payer']);

      const blockRes = await request(app.getHttpServer())
        .post('/admin/compliance/blocked-addresses')
        .set('Cookie', adminCookie)
        .send({ stellar_address: feWPayer, reason: 'e2e wallets cross-reference test' })
        .expect(201);
      blockedId = blockRes.body.id;

      const after = await request(app.getHttpServer()).get('/admin/wallets').set('Cookie', adminCookie).expect(200);
      const afterRow = after.body.find((w: { address: string }) => w.address === feWPayer);
      expect(afterRow.roles.sort()).toEqual(['blocked', 'payer']);
    });
  });

  describe('exchange rate: live rate reachable, and applied conversions are auditable', () => {
    const xrPayer = `G${'EXCHANGERATETEST'.padEnd(55, 'A')}`;

    beforeAll(async () => {
      // A real signed XLM transaction through the actual reconciler isn't
      // practical in this e2e context — this inserts the row the way the
      // fixed reconciler now would (a real fx_rate_to_usd captured
      // alongside the converted amount), to prove the READ side (the admin
      // endpoint) surfaces it correctly. The WRITE side (the conversion
      // itself) has its own real-testnet-verified test in
      // reconciler/src/horizon.rs.
      await pool.query(
        `INSERT INTO payments (merchant_id, muxed_id, muxed_address, payer_address, asset_code, amount_usdc, fx_rate_to_usd, net_usdc, status, paging_token, tx_hash, ledger_sequence)
         VALUES ($1, 113, 'M...xr1', $2, 'XLM', 2.73, 0.273, 2.73, 'paid', $3, 'e2e-xr-tx-1', 1)`,
        [merchantId, xrPayer, `e2e-xr-paging-${Date.now()}`],
      );
    });

    afterAll(async () => {
      await pool.query('DELETE FROM payments WHERE payer_address = $1', [xrPayer]);
    });

    it('live rate endpoint reaches real testnet Horizon and returns a positive rate', async () => {
      const res = await request(app.getHttpServer()).get('/admin/exchange-rate/live').set('Cookie', adminCookie).expect(200);
      expect(res.body.reachable).toBe(true);
      expect(Number(res.body.rate)).toBeGreaterThan(0);
    });

    it('recent conversions includes the XLM payment with its applied rate, not a USDC payment', async () => {
      const res = await request(app.getHttpServer()).get('/admin/exchange-rate/conversions').set('Cookie', adminCookie).expect(200);
      const row = res.body.find((c: { payer_address: string }) => c.payer_address === xrPayer);
      expect(row).toBeDefined();
      expect(row.asset_code).toBe('XLM');
      expect(Number(row.fx_rate_to_usd)).toBeCloseTo(0.273, 5);
    });
  });

  describe('merchant tier: admin can change it, identity verification is not implied', () => {
    it('rejects an invalid tier value outright', async () => {
      await request(app.getHttpServer())
        .patch(`/admin/merchants/${merchantId}/tier`)
        .set('Cookie', adminCookie)
        .send({ risk_tier: 'not-a-real-tier' })
        .expect(400);
    });

    it('accepts a valid tier and it actually takes effect', async () => {
      const res = await request(app.getHttpServer())
        .patch(`/admin/merchants/${merchantId}/tier`)
        .set('Cookie', adminCookie)
        .send({ risk_tier: 'enterprise', reason: 'e2e' })
        .expect(200);
      expect(res.body.risk_tier).toBe('enterprise');

      const list = await request(app.getHttpServer()).get('/admin/merchants').set('Cookie', adminCookie).expect(200);
      const row = list.body.find((m: { id: string }) => m.id === merchantId);
      expect(row.risk_tier).toBe('enterprise');
    });
  });

  describe('referrals: attribution at signup, activation computed from real payment history', () => {
    const referrerEmail = `referrer-e2e-${Date.now()}@example.com`;
    const referredEmail = `referred-e2e-${Date.now()}@example.com`;
    const protectedReferredEmail = `protected-referred-e2e-${Date.now()}@example.com`;
    const noCodeEmail = `no-code-e2e-${Date.now()}@example.com`;
    const stellarAddr = 'GBXBABMFZIJPTOFI6STUXA2FMEXDBB4URBD3VS5XDHKMFHGLJZ5WPQBB';
    let referrerId: string;
    let referrerCode: string;
    let referrerCookie: string;
    let referredId: string;
    let protectedReferredId: string;

    afterAll(async () => {
      await pool.query('DELETE FROM referrals WHERE referrer_id = $1 OR referred_id = $1', [referrerId]);
      await pool.query('DELETE FROM referrals WHERE referred_id = $1', [protectedReferredId]);
      await pool.query('DELETE FROM payments WHERE merchant_id = $1', [referredId]);
      await pool.query('DELETE FROM payments WHERE merchant_id = $1', [protectedReferredId]);
      await pool.query('DELETE FROM merchants WHERE email IN ($1, $2, $3, $4)', [
        referrerEmail,
        referredEmail,
        protectedReferredEmail,
        noCodeEmail,
      ]);
    });

    it('every new merchant gets a referral code automatically, no separate step', async () => {
      const res = await request(app.getHttpServer())
        .post('/auth/signup')
        .send({ email: referrerEmail, password: 'a-real-password-000', name: 'Referrer', stellar_base_address: stellarAddr })
        .expect(201);
      referrerId = res.body.merchant.id;
      referrerCookie = res.headers['set-cookie'][0].split(';')[0];

      const { rows } = await pool.query('SELECT referral_code FROM merchants WHERE id = $1', [referrerId]);
      expect(rows[0].referral_code).toMatch(/^[A-Z2-9]{8}$/);
      referrerCode = rows[0].referral_code;
    });

    it('an invalid referral code does not block signup, and creates no attribution', async () => {
      await request(app.getHttpServer())
        .post('/auth/signup')
        .send({
          email: noCodeEmail,
          password: 'a-real-password-000',
          name: 'No Code',
          stellar_base_address: stellarAddr,
          referral_code: 'NOTAREALCODE',
        })
        .expect(201);

      const { rows } = await pool.query(
        `SELECT 1 FROM referrals r JOIN merchants m ON m.id = r.referred_id WHERE m.email = $1`,
        [noCodeEmail],
      );
      expect(rows.length).toBe(0);
    });

    it('signing up with a real referral code attributes the new merchant to the referrer', async () => {
      const res = await request(app.getHttpServer())
        .post('/auth/signup')
        .send({
          email: referredEmail,
          password: 'a-real-password-000',
          name: 'Referred Merchant',
          stellar_base_address: stellarAddr,
          referral_code: referrerCode,
        })
        .expect(201);
      referredId = res.body.merchant.id;

      const mine = await request(app.getHttpServer()).get('/auth/me/referrals').set('Cookie', referrerCookie).expect(200);
      expect(mine.body.code).toBe(referrerCode);
      const row = mine.body.referrals.find((r: { email: string }) => r.email === referredEmail);
      expect(row).toBeDefined();
      expect(row.activated).toBe(false);
    });

    it('the referred merchant gets the trial discount fields set at signup', async () => {
      const { rows } = await pool.query(
        'SELECT promo_fee_bps, promo_expires_at, promo_volume_cap_usdc FROM merchants WHERE id = $1',
        [referredId],
      );
      expect(rows[0].promo_fee_bps).toBe(0);
      expect(Number(rows[0].promo_volume_cap_usdc)).toBe(500);
      const daysUntilExpiry = (new Date(rows[0].promo_expires_at).getTime() - Date.now()) / (24 * 60 * 60 * 1000);
      expect(daysUntilExpiry).toBeGreaterThan(29);
      expect(daysUntilExpiry).toBeLessThanOrEqual(30);
    });

    it('the referred merchant can see their own active promo via /auth/me/referrals', async () => {
      const login = await request(app.getHttpServer())
        .post('/auth/login')
        .send({ email: referredEmail, password: 'a-real-password-000' })
        .expect(200);
      const referredCookie = login.headers['set-cookie'][0].split(';')[0];

      const mine = await request(app.getHttpServer()).get('/auth/me/referrals').set('Cookie', referredCookie).expect(200);
      expect(mine.body.promo).toEqual(
        expect.objectContaining({ active: true, feeBps: 0, volumeCapUsdc: '500' }),
      );
    });

    it('activation flips to true once the referred merchant has a real paid payment, with no write-time hook', async () => {
      await pool.query(
        `INSERT INTO payments (merchant_id, muxed_id, muxed_address, payer_address, asset_code, amount_usdc, net_usdc, status, paging_token, tx_hash, ledger_sequence)
         VALUES ($1, 114, 'M...ref1', $2, 'USDC', 5, 5, 'paid', $3, 'e2e-referral-tx', 1)`,
        [referredId, 'GDIET4T37N35XU4FY52RMR4Z653WYFITEHGIJXN4VEQTDYR5JSURJDPL', `e2e-referral-paging-${Date.now()}`],
      );

      const mine = await request(app.getHttpServer()).get('/auth/me/referrals').set('Cookie', referrerCookie).expect(200);
      const row = mine.body.referrals.find((r: { email: string }) => r.email === referredEmail);
      expect(row.activated).toBe(true);

      const admin = await request(app.getHttpServer()).get('/admin/referrals').set('Cookie', adminCookie).expect(200);
      const adminRow = admin.body.find((r: { referred_email: string }) => r.referred_email === referredEmail);
      expect(adminRow).toBeDefined();
      expect(adminRow.activated).toBe(true);
      expect(adminRow.referrer_email).toBe(referrerEmail);
    });

    it('the reward sweep grants the referrer a 50%-off, time-only promo exactly once', async () => {
      const before = await pool.query('SELECT fee_bps FROM merchants WHERE id = $1', [referrerId]);
      const baseFeeBps: number = before.rows[0].fee_bps;

      // Calling sweep() directly (it's a plain injectable method) rather
      // than waiting on the real 5-minute @Cron() interval — same reason
      // ChannelKeeperService's sweep() is tested this way.
      const rewards = app.get(ReferralRewardsService);
      await rewards.sweep();

      const referral = await pool.query('SELECT reward_granted_at FROM referrals WHERE referred_id = $1', [referredId]);
      expect(referral.rows[0].reward_granted_at).not.toBeNull();

      const referrer = await pool.query(
        'SELECT promo_fee_bps, promo_expires_at, promo_volume_cap_usdc FROM merchants WHERE id = $1',
        [referrerId],
      );
      expect(referrer.rows[0].promo_fee_bps).toBe(Math.floor(baseFeeBps / 2));
      expect(referrer.rows[0].promo_volume_cap_usdc).toBeNull();
      const daysUntilExpiry = (new Date(referrer.rows[0].promo_expires_at).getTime() - Date.now()) / (24 * 60 * 60 * 1000);
      expect(daysUntilExpiry).toBeGreaterThan(29);
      expect(daysUntilExpiry).toBeLessThanOrEqual(30);

      // Idempotency: a second sweep must not re-grant (reward_granted_at
      // IS NULL is no longer true for this referral, so it's excluded).
      const grantedAtFirst = referral.rows[0].reward_granted_at;
      await rewards.sweep();
      const referralAgain = await pool.query('SELECT reward_granted_at FROM referrals WHERE referred_id = $1', [referredId]);
      expect(referralAgain.rows[0].reward_granted_at).toEqual(grantedAtFirst);
    });

    it('does not downgrade a more favorable active promo when another referral activates', async () => {
      const signup = await request(app.getHttpServer())
        .post('/auth/signup')
        .send({
          email: protectedReferredEmail,
          password: 'a-real-password-000',
          name: 'Protected Referred Merchant',
          stellar_base_address: stellarAddr,
          referral_code: referrerCode,
        })
        .expect(201);
      protectedReferredId = signup.body.merchant.id;

      await pool.query(
        `INSERT INTO payments (merchant_id, muxed_id, muxed_address, payer_address, asset_code, amount_usdc, net_usdc, status, paging_token, tx_hash, ledger_sequence)
         VALUES ($1, 115, 'M...ref2', $2, 'USDC', 5, 5, 'paid', $3, 'e2e-referral-protected-tx', 1)`,
        [protectedReferredId, 'GDIET4T37N35XU4FY52RMR4Z653WYFITEHGIJXN4VEQTDYR5JSURJDPL', `e2e-referral-protected-${Date.now()}`],
      );
      await pool.query(
        `UPDATE merchants
         SET promo_fee_bps = 0, promo_expires_at = NOW() + INTERVAL '30 days', promo_volume_cap_usdc = 500
         WHERE id = $1`,
        [referrerId],
      );
      const before = await pool.query(
        'SELECT promo_fee_bps, promo_expires_at, promo_volume_cap_usdc FROM merchants WHERE id = $1',
        [referrerId],
      );

      await app.get(ReferralRewardsService).sweep();

      const after = await pool.query(
        'SELECT promo_fee_bps, promo_expires_at, promo_volume_cap_usdc FROM merchants WHERE id = $1',
        [referrerId],
      );
      expect(after.rows[0]).toEqual(before.rows[0]);
      const referral = await pool.query('SELECT reward_granted_at FROM referrals WHERE referred_id = $1', [protectedReferredId]);
      expect(referral.rows[0].reward_granted_at).not.toBeNull();
    });
  });

  describe('reconciler: cursor can only move backward', () => {
    let originalCursor: string;

    beforeAll(async () => {
      const res = await request(app.getHttpServer()).get('/admin/reconciler/status').set('Cookie', adminCookie).expect(200);
      originalCursor = res.body.value;
    });

    afterAll(async () => {
      // Restore whatever was there before this suite touched it — this is
      // a single shared, global row, not scoped to this test's own data.
      await pool.query(`UPDATE reconciler_state SET value = $1 WHERE key = 'cursor'`, [originalCursor]);
    });

    it('rejects a non-numeric, non-"now" value outright', async () => {
      await request(app.getHttpServer())
        .post('/admin/reconciler/rewind')
        .set('Cookie', adminCookie)
        .send({ cursor: 'not-a-real-cursor' })
        .expect(400);
    });

    it('accepts moving to a real position (from "now" or backward)', async () => {
      await request(app.getHttpServer()).post('/admin/reconciler/rewind').set('Cookie', adminCookie).send({ cursor: '1000' }).expect(201);
      await request(app.getHttpServer()).post('/admin/reconciler/rewind').set('Cookie', adminCookie).send({ cursor: '500' }).expect(201);
    });

    it('rejects jumping forward past the current position', async () => {
      const res = await request(app.getHttpServer())
        .post('/admin/reconciler/rewind')
        .set('Cookie', adminCookie)
        .send({ cursor: '999999999' })
        .expect(400);
      expect(res.body.message).toMatch(/backward/);
    });

    it('rejects jumping to "now" from a real position — that skips everything unprocessed', async () => {
      const res = await request(app.getHttpServer())
        .post('/admin/reconciler/rewind')
        .set('Cookie', adminCookie)
        .send({ cursor: 'now' })
        .expect(400);
      expect(res.body.message).toMatch(/skips every unprocessed payment/);
    });
  });

  describe('withdrawal attempts: admin visibility, never leaking the anchor token', () => {
    let attemptId: string;
    let terminalAttemptId: string;
    let recentAttemptId: string;
    let getStatus: jest.SpyInstance;

    beforeAll(async () => {
      const { rows } = await pool.query(
        `INSERT INTO withdrawal_attempts (merchant_id, currency, anchor_tx_id, token, last_status, last_polled_at)
         VALUES ($1, 'XLM', 'e2e-anchor-tx-id', 'e2e-fake-token', 'pending', NOW() - INTERVAL '1 minute')
         RETURNING id`,
        [merchantId],
      );
      attemptId = rows[0].id;
      const terminal = await pool.query(
        `INSERT INTO withdrawal_attempts (merchant_id, currency, anchor_tx_id, token, last_status)
         VALUES ($1, 'XLM', 'e2e-terminal-anchor-tx-id', 'e2e-terminal-token', 'completed')
         RETURNING id`,
        [merchantId],
      );
      terminalAttemptId = terminal.rows[0].id;
      const recentlyPolled = await pool.query(
        `INSERT INTO withdrawal_attempts (merchant_id, currency, anchor_tx_id, token, last_status, last_polled_at)
         VALUES ($1, 'XLM', 'e2e-recent-anchor-tx-id', 'e2e-recent-token', 'pending', NOW())
         RETURNING id`,
        [merchantId],
      );
      recentAttemptId = recentlyPolled.rows[0].id;
      getStatus = jest.spyOn(app.get(WithdrawalsService), 'getStatus').mockResolvedValue({ status: 'pending' });
    });

    it('lists it with the merchant joined in, and never exposes the raw token', async () => {
      const res = await request(app.getHttpServer()).get('/admin/withdrawal-attempts').set('Cookie', adminCookie).expect(200);
      const entry = res.body.find((a: { id: string }) => a.id === attemptId);
      expect(entry).toBeDefined();
      expect(entry.merchant_email).toBe(merchantEmail);
      expect(entry.token).toBeUndefined();
      expect(getStatus).toHaveBeenCalledWith('e2e-fake-token', 'e2e-anchor-tx-id');
      const updated = await pool.query('SELECT last_status FROM withdrawal_attempts WHERE id = $1', [attemptId]);
      expect(updated.rows[0].last_status).toBe('pending');
    });

    it('does not refresh terminal attempts', async () => {
      getStatus.mockClear();
      const res = await request(app.getHttpServer()).get('/admin/withdrawal-attempts').set('Cookie', adminCookie).expect(200);
      expect(res.body.find((a: { id: string }) => a.id === terminalAttemptId).last_status).toBe('completed');
      expect(getStatus).not.toHaveBeenCalledWith('e2e-terminal-token', 'e2e-terminal-anchor-tx-id');
    });

    it('does not refresh attempts polled within the recent-poll window', async () => {
      getStatus.mockClear();
      await pool.query('UPDATE withdrawal_attempts SET last_polled_at = NOW() WHERE id = $1', [recentAttemptId]);
      const res = await request(app.getHttpServer()).get('/admin/withdrawal-attempts').set('Cookie', adminCookie).expect(200);
      expect(res.body.find((a: { id: string }) => a.id === recentAttemptId).last_status).toBe('pending');
      expect(getStatus).not.toHaveBeenCalledWith('e2e-recent-token', 'e2e-recent-anchor-tx-id');
    });
  });
});
