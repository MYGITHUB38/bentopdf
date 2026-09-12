import { defineConfig } from 'vitest/config';
import { resolve } from 'path';

export default defineConfig({
  // Build-time globals injected by vite.config.ts `define`. Without them any
  // module that (transitively) imports utils/disabled-tools.ts throws on import
  // under Vitest, which is a test-harness gap, not a source defect.
  define: {
    __SIMPLE_MODE__: 'false',
    __DISABLED_TOOLS__: '[]',
    __DISABLED_EDITOR_CATEGORIES__: '[]',
    __BRAND_NAME__: '"BentoPDF"',
  },

  test: {
    // Enable global test APIs (describe, it, expect, etc.)
    globals: true,

    // Simulate browser environment
    environment: 'jsdom',

    // Setup files to run before tests
    setupFiles: ['./src/tests/setup.ts'],

    // Coverage configuration
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html', 'lcov'],
      reportsDirectory: './coverage',
      exclude: [
        'node_modules/',
        'src/tests/',
        'dist/',
        '*.config.ts',
        '*.config.js',
        '**/*.d.ts',
        'public/',
        'scripts/',
      ],
      // Set thresholds (optional)
      thresholds: {
        lines: 80,
        functions: 80,
        branches: 80,
        statements: 80,
      },
    },

    // Include/exclude patterns
    include: ['src/**/*.{test,spec}.{js,ts}'],
    exclude: ['node_modules', 'dist', '.idea', '.git', '.cache'],

    // Test timeout
    testTimeout: 10000,

    // Watch options
    watch: false,
  },

  resolve: {
    alias: {
      '@': resolve(__dirname, './src'),
    },
  },
});
