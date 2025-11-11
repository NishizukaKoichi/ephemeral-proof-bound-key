import { z } from 'zod';

const ConfigSchema = z.object({
  ISSUER_URL: z.string().url().default('http://localhost:4000'),
  PORT: z.coerce.number().int().positive().default(4000),
  SIGNING_ALG: z.enum(['ES256']).default('ES256'),
});

export type AppConfig = z.infer<typeof ConfigSchema>;

export const config: AppConfig = ConfigSchema.parse({
  ISSUER_URL: process.env.ISSUER_URL,
  PORT: process.env.PORT,
  SIGNING_ALG: process.env.SIGNING_ALG,
});
