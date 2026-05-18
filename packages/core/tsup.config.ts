import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    'auth/index': 'src/auth/index.ts',
    'web/index': 'src/web/index.ts',
    'api/index': 'src/api/index.ts',
    'ai/index': 'src/ai/index.ts',
    'crypto/index': 'src/crypto/index.ts',
    'honeypot/index': 'src/honeypot/index.ts',
    'file/index': 'src/file/index.ts',
    'network/index': 'src/network/index.ts',
    'cloud/index': 'src/cloud/index.ts',
    'monitoring/index': 'src/monitoring/index.ts',
    'defensive/index': 'src/defensive/index.ts',
    'enterprise/index': 'src/enterprise/index.ts',
    'integrations/index': 'src/integrations/index.ts',
  },
  format: ['esm', 'cjs'],
  dts: true,
  splitting: true,
  clean: true,
  sourcemap: true,
  treeshake: true,
  minify: true,
  target: 'node24',
});
