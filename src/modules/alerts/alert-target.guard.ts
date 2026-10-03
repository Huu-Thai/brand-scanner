import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../../config/configuration.js';

export class UnsafeTargetError extends Error {}

const V4_BLOCKED: [string, number][] = [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
];

const v4ToInt = (ip: string) =>
  ip.split('.').reduce((a, o) => (a << 8) + Number(o), 0) >>> 0;

/** True for loopback, private, link-local (incl. cloud metadata), CGNAT, multicast, reserved, documentation. */
export function isNonPublicAddress(address: string): boolean {
  const ip = address.toLowerCase().replace(/^\[|\]$/g, '');
  if (isIP(ip) === 4) {
    const n = v4ToInt(ip);
    return V4_BLOCKED.some(
      ([base, bits]) => n >>> (32 - bits) === v4ToInt(base) >>> (32 - bits),
    );
  }
  if (isIP(ip) !== 6) return true;
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(ip);
  if (mapped) return isNonPublicAddress(mapped[1]);
  return (
    ip === '::' ||
    ip === '::1' ||
    /^f[cd]/.test(ip) || // fc00::/7 unique local
    /^fe[89ab]/.test(ip) || // fe80::/10 link-local
    ip.startsWith('ff') || // multicast
    ip.startsWith('2001:db8') || // documentation
    ip.startsWith('64:ff9b:') // NAT64 (could reach internal v4)
  );
}

/**
 * SSRF guard for webhook / Slack targets. Checked when a channel is saved AND right before each
 * send (DNS can change in between). https only and public addresses only, unless relaxed with
 * ALERT_ALLOW_INSECURE_TARGETS / ALERT_ALLOW_PRIVATE_TARGETS (e.g. an internal webhook relay).
 */
@Injectable()
export class AlertTargetGuard {
  constructor(private readonly config: ConfigService<AppConfig, true>) {}

  protected resolve(host: string): Promise<{ address: string }[]> {
    return lookup(host, { all: true, verbatim: true });
  }

  async assertSafeUrl(raw: string): Promise<URL> {
    const { allowPrivateTargets, allowInsecureTargets } = this.config.get(
      'alerts',
      { infer: true },
    );
    let url: URL;
    try {
      url = new URL(raw);
    } catch {
      throw new UnsafeTargetError('Target must be an absolute URL');
    }
    if (
      url.protocol !== 'https:' &&
      !(allowInsecureTargets && url.protocol === 'http:')
    )
      throw new UnsafeTargetError('Target must use https');
    if (url.username || url.password)
      throw new UnsafeTargetError('Credentials in the URL are not allowed');
    if (allowPrivateTargets) return url;
    const host = url.hostname.replace(/^\[|\]$/g, '');
    let addresses: { address: string }[];
    try {
      addresses = isIP(host) ? [{ address: host }] : await this.resolve(host);
    } catch {
      throw new UnsafeTargetError(`Target host ${host} does not resolve`);
    }
    if (
      !addresses.length ||
      addresses.some((a) => isNonPublicAddress(a.address))
    )
      throw new UnsafeTargetError(
        `Target host ${host} resolves to a non-public address`,
      );
    return url;
  }
}
