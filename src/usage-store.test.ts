import { describe, expect, test } from 'vitest';
import { InMemoryUsageStore, UsageStoreError } from './usage-store.js';

describe('InMemoryUsageStore', () => {
  test('enforces limit and expiry', async () => {
    const store = new InMemoryUsageStore();
    const now = Math.floor(Date.now() / 1000);
    await store.consume('trace', 1, now + 10, now);
    await expect(() => store.consume('trace', 1, now + 10, now)).rejects.toThrowError(UsageStoreError);
    await expect(() => store.consume('trace', 1, now - 1, now + 20)).rejects.toThrowError(UsageStoreError);
  });
});
