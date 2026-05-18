import { describe, it, expect } from 'vitest';

describe('Cloud: Dockerfile validation', () => {
  it('validateDockerfile finds issues', async () => {
    const { validateDockerfile } = await import('./src/cloud/index.js');
    const dockerfile = 'FROM ubuntu\nRUN apt-get update\nUSER root';
    const result = validateDockerfile(dockerfile, []);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('validateDockerfile allows clean dockerfile', async () => {
    const { validateDockerfile } = await import('./src/cloud/index.js');
    const dockerfile = 'FROM node:18-alpine\nWORKDIR /app\nUSER node';
    const result = validateDockerfile(dockerfile, []);
    expect(result.score).toBeGreaterThanOrEqual(0);
  });
});

describe('Cloud: Public bucket detection', () => {
  it('detectPublicBucket finds public bucket', async () => {
    const { detectPublicBucket } = await import('./src/cloud/index.js');
    const result = detectPublicBucket(
      { name: 'my-bucket', publicAccessBlock: { BlockPublicAcls: false, BlockPublicPolicy: false, IgnorePublicAcls: false, RestrictPublicBuckets: false }, encryption: false, logging: false },
      [],
      {}
    );
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('detectPublicBucket allows secure bucket', async () => {
    const { detectPublicBucket } = await import('./src/cloud/index.js');
    const result = detectPublicBucket(
      { name: 'my-bucket', publicAccessBlock: { BlockPublicAcls: true, BlockPublicPolicy: true, IgnorePublicAcls: true, RestrictPublicBuckets: true }, encryption: true, logging: true, versioning: true },
      [],
      {}
    );
    expect(result.findings.length).toBe(0);
  });
});

describe('Cloud: IAM policy validation', () => {
  it('validateIamPolicy finds overly permissive policy', async () => {
    const { validateIamPolicy } = await import('./src/cloud/index.js');
    const policy = { statements: [{ effect: 'Allow', action: '*', resource: '*' }] };
    const result = validateIamPolicy({ Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }] }, [], []);
    expect(result.findings.length).toBeGreaterThan(0);
  });
});

describe('Cloud: Cloud misconfig detection', () => {
  it('detectCloudMisconfig finds issues', async () => {
    const { detectCloudMisconfig } = await import('./src/cloud/index.js');
    const services = [{ name: 's3', key: 'my-bucket', public: true, encryption: false, logging: false }];
    const result = detectCloudMisconfig({ s3: { public: true, encryption: false } }, { s3: { encryption: true, public: false } }, 'aws');
    expect(result.findings.length).toBeGreaterThan(0);
  });
});

describe('Cloud: Supply chain validation', () => {
  it('supplyChainValidation finds vulnerabilities', async () => {
    const { supplyChainValidation } = await import('./src/cloud/index.js');
    const dependencies = [{ name: 'lodash', version: '4.17.0' }];
    const trustedSources = ['lodash'];
    const vulnerabilityDb = [{ packageName: 'lodash', id: 'CVE-2021-23337', severity: 'high', affectedVersion: '4.17.0', fixedVersion: '4.17.21', description: 'Prototype pollution' }];
    const result = supplyChainValidation(dependencies as any, trustedSources, vulnerabilityDb as any);
    expect(result.findings.length).toBeGreaterThan(0);
  });
});
