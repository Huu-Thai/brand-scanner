import { REDACTED, redact, redactString } from './redact.js';

describe('redact', () => {
  it('masks sensitive keys at any depth', () => {
    expect(
      redact({
        password: 'p',
        nested: {
          REDIS_PASSWORD: 'r',
          headers: { authorization: 'Bearer x', 'x-api-key': 'k' },
        },
        list: [{ accessToken: 't' }],
        domain: 'example.com',
      }),
    ).toEqual({
      password: REDACTED,
      nested: {
        REDIS_PASSWORD: REDACTED,
        headers: { authorization: REDACTED, 'x-api-key': REDACTED },
      },
      list: [{ accessToken: REDACTED }],
      domain: 'example.com',
    });
  });

  it('masks credentials inside URLs and bearer tokens in free text', () => {
    expect(
      redactString('connect postgresql://fuzzer:s3cret@db:5432/x failed'),
    ).toBe(`connect postgresql://fuzzer:${REDACTED}@db:5432/x failed`);
    expect(redactString('redis://:hunter2@redis:6379')).toBe(
      `redis://:${REDACTED}@redis:6379`,
    );
    expect(redactString('Authorization: Bearer abc.def.ghi')).toBe(
      `Authorization: Bearer ${REDACTED}`,
    );
  });

  it('leaves non-sensitive values and errors untouched', () => {
    const err = new Error('x');
    expect(redact(err)).toBe(err);
    expect(redact(42)).toBe(42);
    expect(redact(null)).toBeNull();
  });
});
