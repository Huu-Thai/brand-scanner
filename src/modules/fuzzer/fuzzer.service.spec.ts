import { parseLines } from './dictionary.loader.js';
import { FuzzerService } from './fuzzer.service.js';

describe('FuzzerService', () => {
  const service = new FuzzerService();
  beforeAll(() => service.onModuleInit());

  it('excludes the brand’s own domain by default', () => {
    const perms = service.generate('example.com');
    expect(perms.some((p) => p.fuzzer === '*original')).toBe(false);
    expect(perms.some((p) => p.domain === 'example.com')).toBe(false);
  });

  it('restricts output to the requested techniques', () => {
    const perms = service.generate('example.com', {
      fuzzers: ['omission', 'transposition'],
    });
    expect(new Set(perms.map((p) => p.fuzzer))).toEqual(
      new Set(['omission', 'transposition']),
    );
  });

  it('refuses to run before dictionaries are loaded', () => {
    expect(() => new FuzzerService().generate('example.com')).toThrow(
      /before initialisation/,
    );
  });

  it('parses dictionary files like Reporting (comments and blanks dropped)', () => {
    expect(parseLines('# c\n// c\n\n  login \nsecure\r\n')).toEqual([
      'login',
      'secure',
    ]);
  });
});
