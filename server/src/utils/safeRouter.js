const express = require('express');
const { asyncHandler } = require('./asyncHandler');

/**
 * Drop-in replacement for express.Router() that automatically applies
 * asyncHandler to any `async function` handler registered via
 * .get/.post/.patch/.delete — so every route in the app is protected from
 * crashing the whole process on an unhandled promise rejection, without
 * having to remember to wrap each one by hand (and without risking breaking
 * existing route bodies by editing them directly).
 *
 * Non-async functions (requireAuth, requireRole('admin'), etc.) are left
 * completely untouched, since they're synchronous middleware, not the thing
 * this is protecting against.
 */
function safeRouter() {
  const router = express.Router();

  ['get', 'post', 'put', 'patch', 'delete'].forEach((method) => {
    const original = router[method].bind(router);
    router[method] = (path, ...handlers) => {
      const wrapped = handlers.map((h) =>
        typeof h === 'function' && h.constructor && h.constructor.name === 'AsyncFunction'
          ? asyncHandler(h)
          : h
      );
      return original(path, ...wrapped);
    };
  });

  return router;
}

module.exports = { safeRouter };
