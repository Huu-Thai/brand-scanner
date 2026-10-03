import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../../config/configuration.js';

export type IndicatorType = 'DOMAIN' | 'IPV4' | 'IPV6' | 'URL';

export interface ThreatFeedIndicator {
  id: string;
  value: string;
  type: IndicatorType;
  severity: string | null;
  confidence: number | null;
  isActive: boolean;
  tags: string[];
}

export interface NewIndicator {
  value: string;
  type: IndicatorType;
  sourceId: string;
  severity?: string;
  confidence?: number;
  tags?: string[];
  isActive?: boolean;
}

export class ThreatFeedError extends Error {
  constructor(
    message: string,
    readonly status?: number,
  ) {
    super(message);
  }
}

/**
 * Service-to-service client for the threat-feed API (the backend behind manage-feed).
 * Signs in with a dedicated service account; the JWT is cached until shortly before it
 * expires and refreshed once on a 401.
 */
@Injectable()
export class ThreatFeedClient {
  private readonly logger = new Logger(ThreatFeedClient.name);
  private token?: { value: string; expiresAt: number };
  private login?: Promise<string>;
  private resolvedSourceId?: string;

  constructor(private readonly config: ConfigService<AppConfig, true>) {}

  get enabled(): boolean {
    return this.settings.enabled;
  }

  private get settings() {
    return this.config.get('threatFeed', { infer: true });
  }

  /** Exact, case-insensitive match among active indicators of `type`. */
  async findActiveIndicator(
    type: IndicatorType,
    value: string,
  ): Promise<ThreatFeedIndicator | null> {
    const params = new URLSearchParams({
      type,
      search: value,
      isActive: 'true',
      limit: '100',
    });
    const page = await this.request<{ data: ThreatFeedIndicator[] }>(
      `/feeds?${params}`,
    );
    const wanted = value.toLowerCase();
    return page.data.find((i) => i.value.toLowerCase() === wanted) ?? null;
  }

  /** Any indicator (active or not) with exactly this value and type. */
  async findIndicator(
    type: IndicatorType,
    value: string,
  ): Promise<ThreatFeedIndicator | null> {
    const params = new URLSearchParams({ type, search: value, limit: '100' });
    const page = await this.request<{ data: ThreatFeedIndicator[] }>(
      `/feeds?${params}`,
    );
    const wanted = value.toLowerCase();
    return page.data.find((i) => i.value.toLowerCase() === wanted) ?? null;
  }

  createIndicator(input: NewIndicator): Promise<ThreatFeedIndicator> {
    return this.request('/feeds', { method: 'POST', body: input });
  }

  updateIndicator(
    id: string,
    changes: Partial<Omit<NewIndicator, 'sourceId'>>,
  ): Promise<ThreatFeedIndicator> {
    return this.request(`/feeds/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      body: changes,
    });
  }

  /** Id of the source indicators are published under (configured, looked up by name, or created). */
  async sourceId(): Promise<string> {
    const { sourceId, sourceName } = this.settings;
    if (sourceId) return sourceId;
    if (this.resolvedSourceId) return this.resolvedSourceId;
    const sources =
      await this.request<{ id: string; name: string }[]>('/sources');
    const found = sources.find((s) => s.name === sourceName);
    const id =
      found?.id ??
      (
        await this.request<{ id: string }>('/sources', {
          method: 'POST',
          body: {
            name: sourceName,
            type: 'fuzzer_scanner',
            params: { description: 'Look-alike domains confirmed by analysts' },
          },
        })
      ).id;
    if (!found) this.logger.log(`Created threat-feed source "${sourceName}"`);
    this.resolvedSourceId = id;
    return id;
  }

  private async request<T>(
    path: string,
    init: { method?: string; body?: unknown } = {},
    retried = false,
  ): Promise<T> {
    const { url, timeoutMs } = this.settings;
    const token = await this.accessToken();
    const res = await fetch(`${url}${path}`, {
      method: init.method ?? 'GET',
      headers: {
        authorization: `Bearer ${token}`,
        accept: 'application/json',
        ...(init.body === undefined
          ? {}
          : { 'content-type': 'application/json' }),
      },
      body: init.body === undefined ? undefined : JSON.stringify(init.body),
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (res.status === 401 && !retried) {
      this.token = undefined;
      return this.request<T>(path, init, true);
    }
    if (!res.ok) {
      const route = `${init.method ?? 'GET'} ${path.split('?')[0]}`;
      throw new ThreatFeedError(
        res.status === 403
          ? `threat-feed ${route} → HTTP 403: the service account's role lacks this permission`
          : `threat-feed ${route} → HTTP ${res.status}`,
        res.status,
      );
    }
    return (await res.json()) as T;
  }

  private async accessToken(): Promise<string> {
    if (this.token && Date.now() < this.token.expiresAt)
      return this.token.value;
    // Single-flight: concurrent callers share one login request.
    this.login ??= this.signIn().finally(() => (this.login = undefined));
    return this.login;
  }

  private async signIn(): Promise<string> {
    const { url, email, password, timeoutMs } = this.settings;
    const res = await fetch(`${url}/auth/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email, password }),
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok)
      throw new ThreatFeedError(
        `threat-feed login failed: HTTP ${res.status}`,
        res.status,
      );
    const { accessToken } = (await res.json()) as { accessToken: string };
    this.token = {
      value: accessToken,
      expiresAt: jwtExpiry(accessToken) - 30_000,
    };
    this.logger.log('Signed in to threat-feed');
    return accessToken;
  }
}

/** `exp` claim in ms; defaults to 5 minutes from now when absent/unreadable. */
export function jwtExpiry(token: string): number {
  try {
    const payload = JSON.parse(
      Buffer.from(token.split('.')[1], 'base64url').toString('utf8'),
    ) as { exp?: number };
    if (typeof payload.exp === 'number') return payload.exp * 1000;
  } catch {
    // fall through
  }
  return Date.now() + 5 * 60_000;
}
