import type { NextConfig } from "next";

// Ensure node is in PATH for Turbopack's PostCSS subprocess
if (!process.env.PATH?.includes("/opt/homebrew/Cellar/node")) {
  process.env.PATH = `/opt/homebrew/Cellar/node/25.6.0/bin:${process.env.PATH}`;
}

const nextConfig: NextConfig = {
  output: "standalone",
};

export default nextConfig;
