import type { Config } from 'jest';

const config: Config = {
  displayName: 'Multi-Tenant Messaging API',
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src', '<rootDir>/test'],
  testMatch: [
    '**/__tests__/**/*.+(ts|tsx|js)',
    '**/*.(test|spec).+(ts|tsx|js)',
  ],
  transform: {
    '^.+\\.(ts|tsx)$': 'ts-jest',
  },
  collectCoverageFrom: [
    'src/**/*.{ts,tsx}',
    '!src/**/*.d.ts',
    '!src/**/*.interface.ts',
    '!src/**/*.enum.ts',
    '!src/main.ts',
    '!src/**/*.module.ts',
    '!src/**/*.config.ts',
    '!src/migrations/**',
  ],
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'html', 'json'],
  coverageThreshold: {
    global: {
      branches: 90,
      functions: 90,
      lines: 90,
      statements: 90,
    },
  },
  moduleNameMapper: {
    '^@/(.*)$': '<rootDir>/src/$1',
    '^@/common/(.*)$': '<rootDir>/src/common/$1',
    '^@/config/(.*)$': '<rootDir>/src/config/$1',
    '^@/auth/(.*)$': '<rootDir>/src/auth/$1',
    '^@/users/(.*)$': '<rootDir>/src/users/$1',
    '^@/tenants/(.*)$': '<rootDir>/src/tenants/$1',
    '^@/waha/(.*)$': '<rootDir>/src/waha/$1',
    '^@/messages/(.*)$': '<rootDir>/src/messages/$1',
    '^@/webhooks/(.*)$': '<rootDir>/src/webhooks/$1',
  },
  setupFilesAfterEnv: ['<rootDir>/test/setup.ts'],
  testTimeout: 30000,
  maxWorkers: '50%',
  verbose: true,
  forceExit: true,
  clearMocks: true,
  resetMocks: true,
  restoreMocks: true,
};

export default config;