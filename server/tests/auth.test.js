/**
 * Example test — expand this significantly for your submission. At minimum you
 * should have tests covering: registration validation, login lockout after N
 * failed attempts, MFA verify success/failure, booking hold race condition
 * (two concurrent holds on the same room/dates), IDOR (guest A can't fetch
 * guest B's booking), and RBAC (staff can't hit /admin routes).
 */
const request = require('supertest');
const app = require('../src/index');
const { pool } = require('../src/config/db');

afterAll(async () => {
  await pool.end();
});

describe('health check', () => {
  it('responds 200 on /health', async () => {
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
  });
});

describe('auth validation', () => {
  it('rejects registration with a weak password', async () => {
    const res = await request(app).post('/auth/register').send({
      email: 'test@example.com',
      password: 'short',
      fullName: 'Test User',
    });
    expect(res.status).toBe(400);
  });

  it('rejects login with missing fields', async () => {
    const res = await request(app).post('/auth/login').send({});
    expect(res.status).toBe(400);
  });
});
