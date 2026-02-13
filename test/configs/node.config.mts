import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    reporters: "verbose",
    testTimeout: 10000,
    coverage: {
      reporter: ["text"],
      provider: "istanbul",
      include: ["src/**/*.ts"],
    },
    environment: "node",
  },
});
