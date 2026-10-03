import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  Builder,
  error as seleniumError,
  type WebDriver,
} from 'selenium-webdriver';
import * as chrome from 'selenium-webdriver/chrome.js';
import type { AppConfig } from '../../../config/configuration.js';
import { probeStatus } from './http-probe.js';
import { collectPageSignals, type PageSignals } from './page-signals.js';

export interface CaptureResult {
  png: Buffer;
  requestedUrl: string;
  finalUrl: string;
  pageTitle: string | null;
  httpStatus: number | null;
  /** Page contents seen by the browser (absent when collection is not possible). */
  signals?: PageSignals;
}

/** The site itself is unreachable (definitive) — as opposed to Grid trouble (retryable). */
export class SiteUnreachableError extends Error {}

/** Chrome network errors: the site can't be reached over this scheme. */
export const SITE_ERRORS =
  /ERR_NAME_NOT_RESOLVED|ERR_CONNECTION_(REFUSED|RESET|CLOSED|TIMED_OUT)|ERR_ADDRESS_UNREACHABLE|ERR_SSL_PROTOCOL_ERROR|ERR_EMPTY_RESPONSE|ERR_TOO_MANY_REDIRECTS|ERR_CERT_|ERR_NAME_RESOLUTION_FAILED|ERR_TIMED_OUT/i;

/** Page-load timeout: the page is slow, not absent — capture what has rendered. */
export const isLoadTimeout = (e: unknown) =>
  e instanceof seleniumError.TimeoutError ||
  /Timed out receiving message from renderer|timeout: Timed out/i.test(
    (e as Error)?.message ?? '',
  );

/**
 * Captures a look-alike's landing page in an isolated Selenium Grid session (one fresh
 * session per capture, always quit). Tries https:// then http://.
 */
@Injectable()
export class SeleniumCaptureService {
  private readonly logger = new Logger(SeleniumCaptureService.name);

  constructor(private readonly config: ConfigService<AppConfig, true>) {}

  async capture(domain: string): Promise<CaptureResult> {
    const driver = await this.newSession();
    try {
      let lastError: Error | undefined;
      for (const url of [`https://${domain}/`, `http://${domain}/`]) {
        try {
          try {
            await driver.get(url);
          } catch (e) {
            if (!isLoadTimeout(e)) throw e;
            // Slow page (ads, trackers, long-polling): stop loading and keep the partial render.
            await driver.executeScript('window.stop();').catch(() => undefined);
          }
          const [finalUrl, title, base64, httpStatus] = await Promise.all([
            driver.getCurrentUrl(),
            driver.getTitle().catch(() => ''),
            driver.takeScreenshot(),
            probeStatus(url),
          ]);
          const signals = await collectPageSignals(driver);
          return {
            png: Buffer.from(base64, 'base64'),
            requestedUrl: url,
            finalUrl,
            pageTitle: title?.trim().slice(0, 500) || null,
            httpStatus,
            signals,
          };
        } catch (e) {
          lastError = e as Error;
          if (!SITE_ERRORS.test(lastError.message)) throw lastError; // Grid/session problem → retry job
        }
      }
      throw new SiteUnreachableError(
        `${domain} unreachable over https and http: ${firstLine(lastError?.message)}`,
      );
    } finally {
      await driver
        .quit()
        .catch((e: Error) =>
          this.logger.warn(`Selenium quit failed: ${e.message}`),
        );
    }
  }

  protected async newSession(): Promise<WebDriver> {
    const { url } = this.config.get('selenium', { infer: true });
    const pageLoad = this.config.get('enrichment', {
      infer: true,
    }).screenshotPageTimeoutMs;
    const options = new chrome.Options();
    options.addArguments(
      '--headless=new',
      '--no-sandbox',
      '--disable-dev-shm-usage',
      '--disable-gpu',
      '--window-size=1366,768',
      '--mute-audio',
    );
    options.setUserPreferences({
      download_restrictions: 3,
      'profile.default_content_setting_values.notifications': 2,
    });
    options.setAcceptInsecureCerts(true); // phishing sites routinely have bad TLS
    options.setAlertBehavior('dismiss');
    // DOMContentLoaded is enough for a landing-page capture and avoids waiting on every ad/tracker.
    options.setPageLoadStrategy('eager');
    const driver = await new Builder()
      .usingServer(url)
      .forBrowser('chrome')
      .setChromeOptions(options)
      .build();
    await driver
      .manage()
      .setTimeouts({ pageLoad, script: 10_000, implicit: 0 });
    return driver;
  }
}

const firstLine = (s?: string) =>
  (s ?? 'unknown error').split('\n')[0].slice(0, 300);
