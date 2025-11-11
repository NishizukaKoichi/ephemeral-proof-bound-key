export interface UsageStore {
  consume(trace: string, limit: number, exp: number, now: number): Promise<void>;
}

export class UsageStoreError extends Error {
  constructor(public code: 'token_expired' | 'limit_exhausted', message: string) {
    super(message);
  }
}

type UsageRecord = {
  used: number;
  limit: number;
  exp: number;
};

export class InMemoryUsageStore implements UsageStore {
  private records = new Map<string, UsageRecord>();

  constructor(private readonly maxEntries = 10_000) {}

  async consume(trace: string, limit: number, exp: number, now: number): Promise<void> {
    this.evictExpired(now);
    const record = this.records.get(trace) ?? { used: 0, limit, exp };

    if (now > record.exp) {
      this.records.delete(trace);
      throw new UsageStoreError('token_expired', 'token expired before consumption');
    }

    if (record.used >= record.limit) {
      throw new UsageStoreError('limit_exhausted', 'cap.limit exhausted for trace');
    }

    record.used += 1;
    record.limit = limit;
    record.exp = exp;
    this.records.set(trace, record);

    if (this.records.size > this.maxEntries) {
      this.trimOldest();
    }
  }

  private evictExpired(now: number) {
    for (const [trace, record] of this.records.entries()) {
      if (now > record.exp) {
        this.records.delete(trace);
      }
    }
  }

  private trimOldest() {
    const oldestKey = this.records.keys().next().value;
    if (oldestKey) {
      this.records.delete(oldestKey);
    }
  }
}
