import { createHmac } from 'node:crypto';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createTransport, type Transporter } from 'nodemailer';
import type { AppConfig } from '../../../config/configuration.js';
import type { AlertChannelType } from '../../../database/generated/prisma/enums.js';
import { AlertTargetGuard, UnsafeTargetError } from '../alert-target.guard.js';
import { EVENT_TITLES, headline, type AlertPayload } from '../alert.types.js';

export interface ResolvedChannel {
  id: string;
  name: string;
  type: AlertChannelType;
  /** Decrypted target: URL, or comma-separated e-mail addresses. */
  target: string;
  signingSecret: string | null;
}

/** A delivery error that retrying cannot fix (bad URL, 4xx, unsafe target, no SMTP). */
export class PermanentDeliveryError extends Error {}

/** Renders and sends one alert (or a digest of alerts) to a channel. */
@Injectable()
export class AlertSender {
  private mailer?: Transporter;

  constructor(
    private readonly config: ConfigService<AppConfig, true>,
    private readonly guard: AlertTargetGuard,
  ) {}

  async send(
    channel: ResolvedChannel,
    alerts: AlertPayload[],
    deliveryIds: string[],
  ): Promise<void> {
    if (!alerts.length) return;
    if (channel.type === 'EMAIL') return this.sendEmail(channel, alerts);
    let url: URL;
    try {
      url = await this.guard.assertSafeUrl(channel.target);
    } catch (e) {
      throw e instanceof UnsafeTargetError
        ? new PermanentDeliveryError(e.message)
        : e;
    }
    const body =
      channel.type === 'SLACK'
        ? JSON.stringify(slackMessage(alerts))
        : JSON.stringify(
            alerts.length === 1
              ? { type: 'fuzzer.alert', id: deliveryIds[0], alert: alerts[0] }
              : { type: 'fuzzer.alert.digest', ids: deliveryIds, alerts },
          );
    const headers: Record<string, string> = {
      'content-type': 'application/json',
      'user-agent': 'fuzzer-scanner-alerts/1',
    };
    if (channel.type === 'WEBHOOK' && channel.signingSecret) {
      const ts = Math.floor(Date.now() / 1000).toString();
      headers['x-fuzzer-timestamp'] = ts;
      headers['x-fuzzer-signature'] =
        `sha256=${signature(channel.signingSecret, ts, body)}`;
    }
    let res: Response;
    try {
      res = await fetch(url, {
        method: 'POST',
        headers,
        body,
        redirect: 'manual', // a redirect could point anywhere — never follow it
        signal: AbortSignal.timeout(
          this.config.get('alerts', { infer: true }).timeoutMs,
        ),
      });
    } catch (e) {
      throw new Error(`${url.host}: ${(e as Error).message}`);
    }
    if (res.ok) return;
    const msg = `${url.host} → HTTP ${res.status}`;
    if (
      res.status >= 400 &&
      res.status < 500 &&
      res.status !== 408 &&
      res.status !== 429
    )
      throw new PermanentDeliveryError(msg);
    throw new Error(msg);
  }

  private async sendEmail(
    channel: ResolvedChannel,
    alerts: AlertPayload[],
  ): Promise<void> {
    const { smtpUrl, emailFrom } = this.config.get('alerts', { infer: true });
    if (!smtpUrl)
      throw new PermanentDeliveryError('E-mail channels need SMTP_URL');
    this.mailer ??= createTransport(smtpUrl);
    const subject =
      alerts.length === 1
        ? headline(alerts[0])
        : `Fuzzer Scanner digest: ${alerts.length} look-alike alerts`;
    await this.mailer.sendMail({
      from: emailFrom,
      to: channel.target,
      subject,
      text: alerts.map(textBlock).join('\n\n'),
      html: `<div style="font-family:system-ui,sans-serif">${alerts.map(htmlBlock).join('<hr>')}</div>`,
    });
  }
}

export function signature(
  secret: string,
  timestamp: string,
  body: string,
): string {
  return createHmac('sha256', secret)
    .update(`${timestamp}.${body}`)
    .digest('hex');
}

function textBlock(a: AlertPayload): string {
  return [
    headline(a),
    `Status: ${a.status} · threat level: ${a.threatLevel} · technique: ${a.fuzzer}`,
    ...a.details.map((d) => `- ${d}`),
    a.consoleUrl ? `Open: ${a.consoleUrl}` : '',
  ]
    .filter(Boolean)
    .join('\n');
}

const esc = (s: string) =>
  s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

function htmlBlock(a: AlertPayload): string {
  return `<p><strong>${esc(EVENT_TITLES[a.eventType])}</strong>: <code>${esc(a.domain)}</code> imitates <strong>${esc(a.brand)}</strong> — risk ${a.riskScore} (${esc(a.threatLevel)})</p>${
    a.details.length
      ? `<ul>${a.details.map((d) => `<li>${esc(d)}</li>`).join('')}</ul>`
      : ''
  }${a.consoleUrl ? `<p><a href="${esc(a.consoleUrl)}">Open in the console</a></p>` : ''}`;
}

function slackMessage(alerts: AlertPayload[]) {
  const line = (a: AlertPayload) =>
    `*${EVENT_TITLES[a.eventType]}* — \`${a.domain}\` imitates *${a.brand}* · risk ${a.riskScore} (${a.threatLevel})${
      a.consoleUrl ? ` · <${a.consoleUrl}|open>` : ''
    }`;
  return {
    text:
      alerts.length === 1
        ? headline(alerts[0])
        : `${alerts.length} look-alike alerts`,
    blocks: [
      ...(alerts.length > 1
        ? [
            {
              type: 'header',
              text: {
                type: 'plain_text',
                text: `Fuzzer Scanner digest — ${alerts.length} alerts`,
              },
            },
          ]
        : []),
      ...alerts.slice(0, 45).map((a) => ({
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: [line(a), ...a.details.slice(0, 5).map((d) => `• ${d}`)].join(
            '\n',
          ),
        },
      })),
      ...(alerts.length > 45
        ? [
            {
              type: 'context',
              elements: [
                { type: 'mrkdwn', text: `…and ${alerts.length - 45} more` },
              ],
            },
          ]
        : []),
    ],
  };
}
