import { EKeyVerificationError } from './errors.js';

export interface ClientCertificateInfo {
  fingerprint: string;
  subject?: string;
  spiffeId?: string;
}

export interface CertificateExtractor {
  extract(request: { socket?: { getPeerCertificate?: () => ClientCertificateInfo | null; authorized?: boolean } }):
    | ClientCertificateInfo
    | null;
}

export class NodeTlsCertificateExtractor implements CertificateExtractor {
  extract(request: { socket?: { getPeerCertificate?: () => any; authorized?: boolean } }): ClientCertificateInfo | null {
    const cert = request.socket?.getPeerCertificate?.();
    if (!cert || Object.keys(cert).length === 0) {
      return null;
    }
    return {
      fingerprint: cert.fingerprint256?.replace(/:/g, '').toLowerCase(),
      subject: cert.subject?.CN,
      spiffeId: cert.subjectaltname?.replace('URI:', ''),
    };
  }
}

export function ensureClientCertificate(
  extractor: CertificateExtractor,
  request: { socket?: { getPeerCertificate?: () => ClientCertificateInfo | null; authorized?: boolean } },
): ClientCertificateInfo {
  if (!request.socket?.authorized) {
    throw new EKeyVerificationError('invalid_request', 'mTLS connection not authorized');
  }

  const cert = extractor.extract(request);
  if (!cert?.fingerprint) {
    throw new EKeyVerificationError('invalid_request', 'client certificate fingerprint missing');
  }

  return cert;
}
