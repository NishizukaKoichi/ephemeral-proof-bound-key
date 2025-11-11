export type VerificationErrorCode =
  | 'invalid_request'
  | 'invalid_token'
  | 'expired_token'
  | 'capability_mismatch'
  | 'replay_detected'
  | 'invalid_proof';

export class EKeyVerificationError extends Error {
  constructor(public readonly code: VerificationErrorCode, message: string, public readonly details?: Record<string, unknown>) {
    super(message);
  }
}
