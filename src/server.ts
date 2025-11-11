import Fastify, { FastifyServerOptions } from 'fastify';
import { config } from './config.js';
import { issueToken, TokenRequestSchema } from './issuer.js';
import { ensureClientCertificate, NodeTlsCertificateExtractor } from './mtls.js';

const certExtractor = new NodeTlsCertificateExtractor();

export function buildServer(options: FastifyServerOptions = {}) {
  const app = Fastify({ ...options, logger: options.logger ?? true });

  app.post('/token', async (request, reply) => {
    let body = request.body as Record<string, unknown> | undefined;
    const bindMode = (body?.['bind'] as string | undefined) ?? 'DPoP';
    if (bindMode === 'mTLS') {
      try {
        const cert = ensureClientCertificate(certExtractor, request.raw as any);
        body = { ...body, cert_fingerprint: cert.fingerprint };
      } catch (error) {
        request.log.warn({ err: error }, 'client certificate extraction failed');
        reply.status(401).send({ error: (error as Error).message });
        return;
      }
    }

    const parsed = TokenRequestSchema.safeParse(body);

    if (!parsed.success) {
      reply.status(400).send({
        error: 'invalid_request',
        details: parsed.error.issues.map((issue) => ({
          path: issue.path.join('.'),
          message: issue.message,
        })),
      });
      return;
    }

    try {
      const response = await issueToken(parsed.data);
      reply.status(201).send(response);
    } catch (error) {
      request.log.error({ err: error }, 'failed_to_issue_token');
      reply.status(500).send({ error: 'server_error' });
    }
  });

  return app;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const app = buildServer();
  app
    .listen({ port: config.PORT, host: '0.0.0.0' })
    .then(() => {
      app.log.info(`E-Key issuer listening on ${config.PORT}`);
    })
    .catch((err) => {
      app.log.error(err);
      process.exit(1);
    });
}
