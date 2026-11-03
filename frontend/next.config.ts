import type { NextConfig } from "next";

// Django backend (API + WebSocket). Override with BACKEND_URL in production.
const BACKEND_URL = process.env.BACKEND_URL ?? "http://127.0.0.1:8000";

const nextConfig: NextConfig = {
  // This is a token-authenticated, client-rendered dashboard: nothing to prerender per user.
  cacheComponents: false,
  // Django routes end with "/"; keep them intact instead of redirecting.
  skipTrailingSlashRedirect: true,
  output: "standalone",
  // Allow opening the dev server via 127.0.0.1 as well as localhost.
  allowedDevOrigins: ["127.0.0.1", "localhost"],
  // Tailwind v4 is compiled by its Turbopack loader (no PostCSS config in this project).
  turbopack: {
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
  async rewrites() {
    return [{ source: "/api/:path*", destination: `${BACKEND_URL}/api/:path*/` }];
  },
};

export default nextConfig;
