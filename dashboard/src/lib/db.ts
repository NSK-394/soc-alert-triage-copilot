import postgres from 'postgres';

// Single shared connection pool for the whole server process. Next.js reuses
// modules across requests within one server instance, so this is created once.
// DATABASE_URL is injected at runtime by docker-compose (see root docker-compose.yml);
// never bake credentials into the built image.
declare global {
  // eslint-disable-next-line no-var
  var __socDashboardSql: ReturnType<typeof postgres> | undefined;
}

function createClient() {
  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) {
    throw new Error('DATABASE_URL is not set');
  }
  return postgres(connectionString, {
    // Keep the pool small; this is a low-traffic internal dashboard.
    max: 5,
    idle_timeout: 20,
    connect_timeout: 10,
  });
}

function getClient(): ReturnType<typeof postgres> {
  if (!globalThis.__socDashboardSql) {
    globalThis.__socDashboardSql = createClient();
  }
  return globalThis.__socDashboardSql;
}

// Lazy proxy: only touches process.env.DATABASE_URL / opens a connection on the
// first real query, not at module import time. Next.js's build step statically
// analyzes the module graph (e.g. for the auto-generated /_not-found page) even
// for routes marked `dynamic = 'force-dynamic'`, which previously made a plain
// eager `createClient()` here throw during `next build` whenever DATABASE_URL
// wasn't set at build time -- it's a runtime-only value injected by docker-compose.
export const sql = new Proxy(function () {} as unknown as ReturnType<typeof postgres>, {
  apply(_target, thisArg, args) {
    return Reflect.apply(getClient(), thisArg, args);
  },
  get(_target, prop, receiver) {
    return Reflect.get(getClient(), prop, receiver);
  },
});
