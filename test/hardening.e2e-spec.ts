import { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import cookieParser from 'cookie-parser';
import * as bcrypt from 'bcryptjs';
import request from 'supertest';
import { AppModule } from '../src/app.module';
import { pool } from '../src/db/pool';
import { MAILER, Mailer, OutgoingMail } from '../src/mail/mailer';

// Covers the abuse and admin controls added in the security pass: the
// bazaar's anonymous submission limits, and the admin-triggered reset.
describe('hardening: bazaar limits and admin password reset (e2e)', () => {
  let app: INestApplication;
  const sent: OutgoingMail[] = [];
  const capture: Mailer = { send: async (mail) => void sent.push(mail) };
  const stamp = Date.now();
  const adminEmail = `hard-admin-${stamp}@example.com`;
  const merchantEmail = `hard-merchant-${stamp}@example.com`;
  const stellar = 'GBXBABMFZIJPTOFI6STUXA2FMEXDBB4URBD3VS5XDHKMFHGLJZ5WPQBB';
  let adminCookie: string;
  let merchantId: string;

  const listing = (url: string) => ({
    kind: 'resource',
    url,
    description: 'a resource for the hardening test',
  });

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(MAILER)
      .useValue(capture)
      .compile();
    app = moduleRef.createNestApplication();
    app.use(cookieParser());
    await app.init();

    await pool.query('INSERT INTO admins (email, password_hash, name) VALUES ($1, $2, $3)', [
      adminEmail,
      await bcrypt.hash('an-admin-password-000', 10),
      'Hardening Admin',
    ]);
    const login = await request(app.getHttpServer())
      .post('/admin/auth/login')
      .send({ email: adminEmail.toUpperCase(), password: 'an-admin-password-000' })
      .expect(200);
    adminCookie = login.headers['set-cookie'][0].split(';')[0];

    const signup = await request(app.getHttpServer())
      .post('/auth/signup')
      .send({ email: merchantEmail, password: 'merchant-password-1', name: 'Hardening', stellar_base_address: stellar })
      .expect(201);
    merchantId = (await pool.query('SELECT id FROM merchants WHERE email = $1', [merchantEmail])).rows[0].id;
    expect(signup.body.merchant.id).toBe(merchantId);
  });

  afterAll(async () => {
    await pool.query('DELETE FROM bazaar_listings WHERE description = $1', ['a resource for the hardening test']);
    await pool.query('DELETE FROM admin_actions WHERE admin_id IN (SELECT id FROM admins WHERE email = $1)', [adminEmail]);
    await pool.query('DELETE FROM admins WHERE email = $1', [adminEmail]);
    await pool.query('DELETE FROM password_reset_tokens WHERE merchant_id = $1', [merchantId]);
    await pool.query('DELETE FROM merchants WHERE email = $1', [merchantEmail]);
    await app.close();
    await pool.end();
  });

  it('bazaar: refuses a plain-http listing URL', async () => {
    await request(app.getHttpServer()).post('/bazaar/listings').send(listing('http://example.com/x')).expect(400);
  });

  it('bazaar: accepts an https listing, then refuses a second pending listing for the same URL', async () => {
    const url = `https://resource-${stamp}.example.com/api`;
    await request(app.getHttpServer()).post('/bazaar/listings').send(listing(url)).expect(201);
    await request(app.getHttpServer()).post('/bazaar/listings').send(listing(url)).expect(409);
  });

  it('admin: records bazaar moderation reasons in the activity feed', async () => {
    const reason = 'listing does not meet the submission criteria';
    const submission = await request(app.getHttpServer())
      .post('/bazaar/listings')
      .send(listing(`https://moderation-${stamp}.example.com/api`))
      .expect(201);

    await request(app.getHttpServer())
      .patch(`/admin/bazaar-listings/${submission.body.id}/status`)
      .set('Cookie', adminCookie)
      .send({ status: 'rejected', reason })
      .expect(200);

    const activity = await request(app.getHttpServer()).get('/admin/activity').set('Cookie', adminCookie).expect(200);
    const entry = activity.body.find((action: { target_id: string }) => action.target_id === submission.body.id);
    expect(entry).toBeDefined();
    expect(entry.action).toBe('bazaar-listing.rejected');
    expect(entry.detail.reason).toBe(reason);
  });

  it('admin: refuses a reset without a reason', async () => {
    await request(app.getHttpServer())
      .post(`/admin/merchants/${merchantId}/password-reset`)
      .set('Cookie', adminCookie)
      .send({})
      .expect(400);
  });

  it('admin: sends a reset for an active merchant and records the reason in the log', async () => {
    const before = sent.length;
    await request(app.getHttpServer())
      .post(`/admin/merchants/${merchantId}/password-reset`)
      .set('Cookie', adminCookie)
      .send({ reason: 'merchant lost access to their email login' })
      .expect(200);
    expect(sent.length).toBe(before + 1);
    expect(sent[sent.length - 1].to).toBe(merchantEmail);

    const log = await pool.query(
      `SELECT action, detail->>'reason' AS reason FROM admin_actions WHERE target_id = $1 AND action = 'merchant.password-reset-sent' ORDER BY created_at DESC LIMIT 1`,
      [merchantId],
    );
    expect(log.rows[0]).toEqual({ action: 'merchant.password-reset-sent', reason: 'merchant lost access to their email login' });
  });

  it('admin: refuses a reset for a suspended merchant', async () => {
    await pool.query(`UPDATE merchants SET status = 'suspended' WHERE id = $1`, [merchantId]);
    await request(app.getHttpServer())
      .post(`/admin/merchants/${merchantId}/password-reset`)
      .set('Cookie', adminCookie)
      .send({ reason: 'should not be sent' })
      .expect(409);
    await pool.query(`UPDATE merchants SET status = 'active' WHERE id = $1`, [merchantId]);
  });
});
