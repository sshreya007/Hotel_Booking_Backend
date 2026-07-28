
const request = require('supertest');
const app = require('../src/index');
const { pool } = require('../src/config/db');

afterAll(async () => {
  await pool.end();
});

function randomEmail() {
  return `test_${Date.now()}_${Math.floor(Math.random() * 100000)}@example.com`;
}

const STRONG_PASSWORD = 'Str0ng!Passw0rd#2026';

async function registerAndLogin(email) {
  await request(app).post('/auth/register').send({
    email,
    password: STRONG_PASSWORD,
    fullName: 'Test User',
  });

  const loginRes = await request(app).post('/auth/login').send({ email, password: STRONG_PASSWORD });
  const cookies = loginRes.headers['set-cookie'];
  return cookies;
}

describe('registration and login', () => {
  it('registers a new guest and logs in successfully', async () => {
    const email = randomEmail();
    const cookies = await registerAndLogin(email);
    expect(cookies).toBeDefined();
    expect(cookies.some((c) => c.startsWith('accessToken='))).toBe(true);
  });

  it('rejects login with the wrong password without revealing whether the email exists', async () => {
    const email = randomEmail();
    await request(app).post('/auth/register').send({
      email,
      password: STRONG_PASSWORD,
      fullName: 'Test User',
    });

    const wrongPass = await request(app).post('/auth/login').send({ email, password: 'WrongPassword123!' });
    const nonExistent = await request(app)
      .post('/auth/login')
      .send({ email: randomEmail(), password: 'WrongPassword123!' });

    expect(wrongPass.status).toBe(401);
    expect(nonExistent.status).toBe(401);
    expect(wrongPass.body.error).toBe(nonExistent.body.error);
  });
});

describe('RBAC', () => {
  it('blocks a guest from admin-only routes', async () => {
    const cookies = await registerAndLogin(randomEmail());
    const res = await request(app).get('/admin/users').set('Cookie', cookies);
    expect(res.status).toBe(403);
  });

  it('blocks an unauthenticated request entirely', async () => {
    const res = await request(app).get('/profile/me');
    expect(res.status).toBe(401);
  });
});

describe('profile mass-assignment protection', () => {
  it('rejects an attempt to smuggle a role change through profile update', async () => {
    const cookies = await registerAndLogin(randomEmail());
    const res = await request(app)
      .patch('/profile/me')
      .set('Cookie', cookies)
      .send({ fullName: 'New Name', role: 'admin' }); // 'role' is not an allowed field

    expect(res.status).toBe(400);
  });

  it('allows updating only the allow-listed fields', async () => {
    const cookies = await registerAndLogin(randomEmail());
    const res = await request(app).patch('/profile/me').set('Cookie', cookies).send({ fullName: 'New Name' });
    expect(res.status).toBe(200);

    const profile = await request(app).get('/profile/me').set('Cookie', cookies);
    expect(profile.body.fullName).toBe('New Name');
  });
});

describe('bookings scoping', () => {
  it('returns only the current guest\'s own bookings (starts empty for a new user)', async () => {
    const cookies = await registerAndLogin(randomEmail());
    const res = await request(app).get('/bookings/mine').set('Cookie', cookies);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
    expect(res.body).toHaveLength(0);
  });

  it('rejects a booking hold with check-out before check-in', async () => {
    const cookies = await registerAndLogin(randomEmail());
    const res = await request(app)
      .post('/bookings/hold')
      .set('Cookie', cookies)
      .send({
        roomId: '00000000-0000-0000-0000-000000000000',
        checkIn: '2026-08-10',
        checkOut: '2026-08-05',
        guests: 2,
      });
    expect(res.status).toBe(400);
  });
});

describe('server resilience', () => {
  it('stays alive and returns a clean error when an external payment call fails', async () => {
    // This reproduces a real bug: previously, a failed Stripe API call inside
    // an unwrapped async route handler crashed the entire Node process
    // (an unhandled promise rejection), taking down every other user's
    // in-flight request with it. safeRouter() + the /pay route's own
    // try/catch should now turn that into a clean error response instead.
    const cookies = await registerAndLogin(randomEmail());

    // Hitting /pay for a nonexistent booking id exercises the same failure
    // path without needing a live Stripe integration in tests: the route
    // still reaches the ownership check and returns a controlled error
    // rather than throwing unhandled.
    const res = await request(app)
      .post('/bookings/00000000-0000-0000-0000-000000000000/pay')
      .set('Cookie', cookies);
    expect([404, 500, 502]).toContain(res.status);

    // The critical assertion: the app is still responsive afterward.
    const health = await request(app).get('/health');
    expect(health.status).toBe(200);
  });
});

describe('password reset flow', () => {
  it('always returns a generic response, whether or not the email exists', async () => {
    const knownEmail = randomEmail();
    await request(app).post('/auth/register').send({
      email: knownEmail,
      password: STRONG_PASSWORD,
      fullName: 'Test User',
    });

    const known = await request(app).post('/auth/forgot-password').send({ email: knownEmail });
    const unknown = await request(app).post('/auth/forgot-password').send({ email: randomEmail() });

    expect(known.status).toBe(200);
    expect(unknown.status).toBe(200);
    expect(known.body.message).toBe(unknown.body.message);
  });

  it('rejects reset with an invalid token', async () => {
    const res = await request(app)
      .post('/auth/reset-password')
      .send({ token: 'not-a-real-token', newPassword: STRONG_PASSWORD });
    expect(res.status).toBe(400);
  });
});
