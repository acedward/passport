import { defineConfig } from "vitest/config";

// The offline simulator suite proves and executes nothing on a network, but a
// cross-contract call still materialises the callee's contract state, which is
// slow enough on the first run to trip vitest's 5 s default.
export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
    testTimeout: 120_000,
    hookTimeout: 120_000,
  },
});
