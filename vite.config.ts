import { defineConfig } from 'vitest/config';

export default defineConfig({
  base: '/crypto-lab-hpke-envelope/',
  build: {
    target: 'es2022',
  },
  test: {
    include: ['src/**/*.test.ts'],
  },
});
