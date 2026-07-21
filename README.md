# SecureStay — Backend API

A secure Express + PostgreSQL API for a hotel booking platform. This repo is the
backend only — the React frontend lives in a separate project and talks to this
API over HTTP.

## What's implemented

- **Auth**: registration, login with account lockout after repeated failures,
  TOTP-based MFA (setup/verify/enable), short-lived JWT access tokens + rotating
  refresh tokens, logout
- **RBAC**: `guest` / `staff` / `admin` roles enforced per-route via middleware
- **IDOR protection**: ownership checks on every booking route (a guest can only
  ever touch their own bookings; staff are scoped to their own hotel)
- **Transactional bookings**: hold → pay (Stripe test mode) → confirm (via
  signature-verified Stripe webhook) → cancel/refund, all wrapped in real DB
  transactions with rollback on failure
- **Encryption at rest**: AES-256-GCM for sensitive profile fields
- **Audit logging**: append-only `audit_logs` table, written on every
  security-relevant action
- **Rate limiting**: tighter limits on auth endpoints, general limits elsewhere
- **CI/CD**: GitHub Actions running lint, `npm audit`, and tests on every push
- **Containerization**: Dockerfile + docker-compose (API + Postgres)

## Folder structure

```
hotel-booking-backend/
├── .github/
│   └── workflows/
│       └── ci.yml                # lint + npm audit + tests on push/PR
├── .gitignore
├── docker-compose.yml            # API + Postgres, one command to run everything
├── README.md
│
├── db/
│   └── schema.sql                # users, hotels, rooms, bookings, payments, audit_logs
│
└── server/
    ├── .env.example               # documents required secrets (never commit real .env)
    ├── .eslintrc.js
    ├── Dockerfile
    ├── package.json
    ├── src/
    │   ├── index.js                # app entry point, wires everything together
    │   ├── config/
    │   │   └── db.js               # Postgres connection pool
    │   ├── middleware/
    │   │   ├── auth.js             # JWT verification + requireRole (RBAC)
    │   │   ├── auditLog.js         # writes to audit_logs table
    │   │   ├── ownership.js        # IDOR defense (booking ownership check)
    │   │   └── rateLimiter.js      # brute-force protection
    │   ├── routes/
    │   │   ├── admin.js            # user list, role changes, audit log viewer
    │   │   ├── auth.js             # register/login/MFA/refresh/logout
    │   │   ├── bookings.js         # hold → pay → confirm → cancel (transactional core)
    │   │   └── rooms.js            # search, staff room creation, hotel bookings list
    │   └── utils/
    │       ├── encryption.js       # AES-256-GCM field encryption
    │       └── passwordPolicy.js   # password strength rules
    └── tests/
        └── auth.test.js            # example Supertest suite (expand this)
```

## Getting started

```bash
cp server/.env.example server/.env   # fill in real secrets, never commit .env
docker compose up --build
```

API runs on `http://localhost:4000`, Postgres on `5432`.

When you build the frontend as a separate project, point it at
`http://localhost:4000` and set `CORS_ORIGIN` in `server/.env` to wherever the
frontend dev server runs (e.g. `http://localhost:3000` for Vite's default).

## Where each rubric requirement lives

| Requirement | Where |
|---|---|
| Secure registration/login | `server/src/routes/auth.js` |
| MFA (TOTP) | `auth.js` — `/mfa/setup`, `/mfa/verify` |
| Brute-force protection | `middleware/rateLimiter.js`, account lockout fields in `users` table |
| RBAC | `middleware/auth.js` (`requireRole`), enforced per-route |
| IDOR protection | `middleware/ownership.js`, used on every `/bookings/:id` route |
| Encryption at rest | `utils/encryption.js`, applied to guest contact fields |
| Password hashing | bcrypt, see `auth.js` |
| Session/JWT handling | `auth.js` + `middleware/auth.js` (short-lived access token + refresh token rotation) |
| Transaction integrity | `routes/bookings.js` (`BEGIN`/`COMMIT`/`ROLLBACK`) |
| Third-party payments | Stripe test mode, webhook signature verification in `bookings.js` |
| Activity logging | `middleware/auditLog.js`, `audit_logs` table |
| CI/CD security checks | `.github/workflows/ci.yml` |
| Containerization | `docker-compose.yml`, `server/Dockerfile` |

## Known gaps to fill in yourself

- Profile management endpoints (view/edit own profile, data export/import)
- Password reset ("forgot password") flow
- `GET /bookings/mine` for guests to list their own bookings
- Passwordless auth as an advanced/bonus feature
- Full automated test suite (only one example file is provided — expand it to
  cover MFA, lockout, IDOR, RBAC, and the booking race condition)
- IP-based blocking/allow-listing (currently only rate limiting is implemented)

## A note on submitting this

Per your assignment brief, AI-generated application logic you can't explain is
penalized. Use this as a reference to learn from, then rebuild it in your own
words across your own commits — that's also what will let you actually defend
it during your pentest write-up.
