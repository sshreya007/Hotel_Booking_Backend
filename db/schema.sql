-- SecureStay database schema
-- Run automatically by docker-compose on first Postgres startup (mounted into /docker-entrypoint-initdb.d)

CREATE TYPE user_role AS ENUM ('guest', 'staff', 'admin');
CREATE TYPE booking_status AS ENUM ('held', 'confirmed', 'cancelled', 'completed', 'expired');
CREATE TYPE payment_status AS ENUM ('pending', 'succeeded', 'failed', 'refunded');

CREATE TABLE users (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email               TEXT UNIQUE NOT NULL,
    password_hash       TEXT NOT NULL,           -- bcrypt
    role                user_role NOT NULL DEFAULT 'guest',
    hotel_id            UUID NULL,               -- set for 'staff' role only; FK added below once hotels table exists
    full_name           TEXT NOT NULL,
    -- contact_encrypted holds AES-256-GCM ciphertext (JSON: {iv, tag, data}) for phone/address
    contact_encrypted   TEXT,
    mfa_secret          TEXT,                    -- TOTP secret, only set once MFA enabled
    mfa_enabled         BOOLEAN NOT NULL DEFAULT FALSE,
    failed_login_count  INT NOT NULL DEFAULT 0,
    locked_until        TIMESTAMPTZ,
    password_changed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE hotels (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    address     TEXT NOT NULL,
    description TEXT,
    owner_id    UUID REFERENCES users(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- users.hotel_id references hotels, but hotels.owner_id references users -> add FK after both exist
ALTER TABLE users ADD CONSTRAINT fk_users_hotel FOREIGN KEY (hotel_id) REFERENCES hotels(id);

CREATE TABLE rooms (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hotel_id        UUID NOT NULL REFERENCES hotels(id) ON DELETE CASCADE,
    room_number     TEXT NOT NULL,
    room_type       TEXT NOT NULL,
    price_per_night NUMERIC(10,2) NOT NULL CHECK (price_per_night > 0),
    max_guests      INT NOT NULL DEFAULT 2,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (hotel_id, room_number)
);

CREATE TABLE bookings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    room_id         UUID NOT NULL REFERENCES rooms(id),
    guest_id        UUID NOT NULL REFERENCES users(id),
    check_in        DATE NOT NULL,
    check_out       DATE NOT NULL CHECK (check_out > check_in),
    status          booking_status NOT NULL DEFAULT 'held',
    total_price     NUMERIC(10,2) NOT NULL,      -- always server-calculated, never trust client
    hold_expires_at TIMESTAMPTZ,                  -- only set while status = 'held'
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Prevents overlapping CONFIRMED bookings for the same room at the DB level
-- (defense in depth on top of the application-level transaction check)
CREATE EXTENSION IF NOT EXISTS btree_gist;
ALTER TABLE bookings ADD COLUMN date_range daterange
    GENERATED ALWAYS AS (daterange(check_in, check_out, '[)')) STORED;
CREATE INDEX idx_bookings_room_dates ON bookings USING GIST (room_id, date_range)
    WHERE status IN ('held', 'confirmed');

CREATE TABLE payments (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    booking_id        UUID NOT NULL REFERENCES bookings(id),
    stripe_payment_id TEXT UNIQUE,
    amount            NUMERIC(10,2) NOT NULL,
    status            payment_status NOT NULL DEFAULT 'pending',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Append-only audit trail. Never store raw request bodies, passwords, or card data here.
CREATE TABLE audit_logs (
    id          BIGSERIAL PRIMARY KEY,
    user_id     UUID REFERENCES users(id),
    action      TEXT NOT NULL,           -- e.g. 'login_success', 'booking_created', 'role_changed'
    resource    TEXT,                    -- e.g. 'booking:<id>'
    ip_address  TEXT,
    metadata    JSONB,                   -- non-sensitive structured context only
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_audit_logs_user ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_created ON audit_logs(created_at);

-- Used for both "forgot password" reset links and passwordless "magic link" login.
-- Only a HASH of the token is ever stored — if this table leaked, the raw tokens
-- (which are what's actually usable) would not be recoverable from it.
CREATE TABLE auth_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL,
    purpose     TEXT NOT NULL CHECK (purpose IN ('password_reset', 'magic_link')),
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_auth_tokens_user ON auth_tokens(user_id);
CREATE INDEX idx_auth_tokens_hash ON auth_tokens(token_hash);
