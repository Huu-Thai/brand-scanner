import { createHash } from 'node:crypto';
import type { WebDriver } from 'selenium-webdriver';

/** What a landing page contains, as seen by the browser (PLAN.md §14 #4). */
export interface PageSignals {
  hasPasswordField: boolean;
  /** Hosts that the page's forms submit to. */
  formActionHosts: string[];
  /** Lower-cased visible text (title + body), capped — enough to spot brand mentions. */
  text: string;
  /** SHA-256 (hex) of the favicon bytes, fetched by the page itself; null if unavailable. */
  faviconHash: string | null;
}

export const TEXT_LIMIT = 2_000;

/* eslint-disable */
// Runs in the page: DOM facts only, nothing sent anywhere.
const DOM_SCRIPT = `
  const abs = (u) => { try { return new URL(u, location.href) } catch { return null } };
  const icon = document.querySelector('link[rel~="icon"]')?.getAttribute('href') || '/favicon.ico';
  const hosts = [...document.forms].map((f) => abs(f.getAttribute('action') || location.href)).filter(Boolean).map((u) => u.host);
  return {
    hasPasswordField: !!document.querySelector('input[type=password]'),
    formActionHosts: [...new Set(hosts)].slice(0, 10),
    text: ((document.title || '') + ' ' + (document.body ? document.body.innerText : '')).slice(0, ${TEXT_LIMIT * 2}),
    favicon: abs(icon)?.href ?? null,
  };`;

// Fetches the favicon from inside the page (same-origin rules apply; cross-origin → null).
const FAVICON_SCRIPT = `
  const done = arguments[arguments.length - 1];
  fetch(arguments[0], { credentials: 'omit' })
    .then((r) => (r.ok ? r.arrayBuffer() : null))
    .then((b) => {
      if (!b || b.byteLength === 0 || b.byteLength > 200000) return done(null);
      let s = '';
      new Uint8Array(b).forEach((x) => (s += String.fromCharCode(x)));
      done(btoa(s));
    })
    .catch(() => done(null));`;
/* eslint-enable */

/** Collects signals from the current page. Never throws: a page that resists yields empty signals. */
export async function collectPageSignals(
  driver: WebDriver,
): Promise<PageSignals> {
  const empty: PageSignals = {
    hasPasswordField: false,
    formActionHosts: [],
    text: '',
    faviconHash: null,
  };
  try {
    const dom = (await driver.executeScript(DOM_SCRIPT)) as {
      hasPasswordField: boolean;
      formActionHosts: string[];
      text: string;
      favicon: string | null;
    };
    let faviconHash: string | null = null;
    if (dom.favicon && /^https?:/.test(dom.favicon)) {
      await driver.manage().setTimeouts({ script: 5_000 });
      const b64 = (await driver
        .executeAsyncScript(FAVICON_SCRIPT, dom.favicon)
        .catch(() => null)) as string | null;
      if (b64)
        faviconHash = createHash('sha256')
          .update(Buffer.from(b64, 'base64'))
          .digest('hex');
    }
    return {
      hasPasswordField: !!dom.hasPasswordField,
      formActionHosts: Array.isArray(dom.formActionHosts)
        ? dom.formActionHosts.map(String).slice(0, 10)
        : [],
      text: String(dom.text ?? '')
        .replace(/\s+/g, ' ')
        .toLowerCase()
        .slice(0, TEXT_LIMIT),
      faviconHash,
    };
  } catch {
    return empty;
  }
}
