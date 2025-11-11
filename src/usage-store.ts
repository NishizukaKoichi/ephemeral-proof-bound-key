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

  async consume(trace: string, limit: number, exp: number, now: number): Promise<void> {
    const existing = this.records.get(trace);

    if (existing && now > existing.exp) {
      this.records.delete(trace);
    }

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
  }
}
