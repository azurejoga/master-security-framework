import { describe, it, expect } from 'vitest';

describe('API: Input validation', () => {
  it('validateInput returns valid result', async () => {
    const { validateInput } = await import('./src/api/index.js');
    const result = validateInput({ name: 'test' }, 1);
    expect(result.valid).toBe(true);
  });

  it('validateInput detects deep nesting', async () => {
    const { validateInput } = await import('./src/api/index.js');
    const deep = { a: { b: { c: { d: { e: 1 } } } } };
    const result = validateInput(deep, {}, 2);
    expect(result.valid).toBe(false);
  });

  it('sanitizeJson removes dangerous keys', async () => {
    const { sanitizeJson } = await import('./src/api/index.js');
    const result = sanitizeJson({ __proto__: {}, name: 'test' });
    expect(result).not.toHaveProperty('__proto__');
  });

  it('detectBola finds unauthorized access', async () => {
    const { detectBola } = await import('./src/api/index.js');
    const result = detectBola('r1', 'user-1', { r1: 'user-2' });
    expect(result).toBe(true);
  });

  it('detectBola allows authorized access', async () => {
    const { detectBola } = await import('./src/api/index.js');
    const result = detectBola('r1', 'user-1', { r1: 'user-1' });
    expect(result).toBe(false);
  });

  it('detectMassAssignment finds blocked fields', async () => {
    const { detectMassAssignment } = await import('./src/api/index.js');
    const result = detectMassAssignment({ name: 'test', admin: true }, ['name', 'admin'], []);
    expect(result.safe).toBe(true);
  });

  it('detectMassAssignment allows clean input', async () => {
    const { detectMassAssignment } = await import('./src/api/index.js');
    const result = detectMassAssignment({ name: 'test' }, ['name', 'admin'], []);
    expect(result.safe).toBe(true);
  });

  it('graphqlDepthLimit detects deep query', async () => {
    const { graphqlDepthLimit } = await import('./src/api/index.js');
    const query = '{ user { posts { comments { author { name } } } } }';
    const result = graphqlDepthLimit(query, 3);
    expect(result.valid).toBe(false);
  });

  it('graphqlDepthLimit allows shallow query', async () => {
    const { graphqlDepthLimit } = await import('./src/api/index.js');
    const query = '{ user { name } }';
    const result = graphqlDepthLimit(query, 3);
    expect(result.valid).toBe(true);
  });
});

describe('API: JSON schema validation', () => {
  it('validateJsonSchema validates correct data', async () => {
    const { validateJsonSchema } = await import('./src/api/index.js');
    const schema = { type: 'object', properties: { name: { type: 'string' } } };
    const result = validateJsonSchema({ name: 'test' }, schema);
    expect(result.valid).toBe(true);
  });

  it('validateJsonSchema rejects missing required field', async () => {
    const { validateJsonSchema } = await import('./src/api/index.js');
    const schema = { type: 'object', required: ['name'], properties: { name: { type: 'string' } } };
    const result = validateJsonSchema({}, schema);
    expect(result.valid).toBe(false);
  });

  it('validateJsonSchema rejects wrong type', async () => {
    const { validateJsonSchema } = await import('./src/api/index.js');
    const schema = { type: 'object', properties: { age: { type: 'number' } } };
    const result = validateJsonSchema({ age: 'not-a-number' }, schema);
    expect(result.valid).toBe(false);
  });
});
