import Fastify from 'fastify';
import { config } from './config.js';
import { issueToken, TokenRequestSchema } from './issuer.js';

export function buildServer() {
  const app = Fastify({ logger: true });

  app.post('/token', async (request, reply) => {
    const parsed = TokenRequestSchema.safeParse(request.body);

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
