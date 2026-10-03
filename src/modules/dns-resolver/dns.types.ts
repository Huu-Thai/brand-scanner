/** Outcome of one record lookup, mapped from c-ares codes to dnspython's branches (Reporting parity). */
export type DnsOutcomeKind =
  'ok' | 'nxdomain' | 'noanswer' | 'servfail' | 'timeout' | 'error';

export type DnsErrorCode = 'NO_NAMESERVERS' | 'TIMEOUT' | 'DNS_EXCEPTION';

export interface DnsResolution {
  domain: string;
  /** NS lookup returned NXDOMAIN — the name does not exist. */
  nxdomain: boolean;
  /**
   * Treated as registered: not NXDOMAIN and at least one record — or a SERVFAIL on NS, which
   * means the registry delegated the name but its nameservers are broken (Python's
   * `is_registered()` counts '!ServFail' the same way).
   */
  registered: boolean;
  a: string[];
  aaaa: string[];
  mx: string[];
  ns: string[];
  /** Lowest TTL across A/AAAA records, or null. */
  ttl: number | null;
  errors: DnsErrorCode[];
}

export interface Resolvable {
  resolveNs(hostname: string): Promise<string[]>;
  resolve4(
    hostname: string,
    options: { ttl: true },
  ): Promise<{ address: string; ttl: number }[]>;
  resolve6(
    hostname: string,
    options: { ttl: true },
  ): Promise<{ address: string; ttl: number }[]>;
  resolveMx(
    hostname: string,
  ): Promise<{ priority: number; exchange: string }[]>;
}
