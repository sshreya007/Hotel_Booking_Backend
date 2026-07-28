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






