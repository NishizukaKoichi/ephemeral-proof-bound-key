export interface AuditEvent {
  sub: string;
  trace: string;
  outcome: 'allowed' | 'replay_blocked' | 'expired' | 'cap_mismatch';
  reason?: string;
  timestamp: number;
}

export interface AuditLogger {
  record(event: AuditEvent): Promise<void>;
}

export class ConsoleAuditLogger implements AuditLogger {
  async record(event: AuditEvent): Promise<void> {
    console.log('[audit]', JSON.stringify(event));
  }
}

export class NoopAuditLogger implements AuditLogger {
  async record(): Promise<void> {
    // intentionally empty
  }
}
