const { Pool } = require('pg');

// A single shared pool. Every query MUST use parameterized placeholders ($1, $2, ...)
// — never string-concatenate user input into SQL. This is our SQL injection defense.
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

pool.on('error', (err) => {
  // eslint-disable-next-line no-console
  console.error('Unexpected Postgres pool error', err);
});

module.exports = { pool };
