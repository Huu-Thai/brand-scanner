// RDAP stub for load tests. Serves an IANA-style bootstrap that maps every TLD the fuzzer can
// produce to a stub "registry", modelled like reality: .com/.net share one registry (Verisign)
// and the remaining TLDs are spread over REGISTRIES other hosts (distinct ports — the RDAP client
// rate-limits per host:port, exactly as it does per registry in production).
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';

const BASE = Number(process.env.RDAP_STUB_PORT ?? 5380);
const REGISTRIES = Number(process.env.REGISTRIES ?? 20);
const LATENCY = Number(process.env.LATENCY_MS ?? 80);
const dict = new URL('../src/modules/fuzzer/dictionaries/', import.meta.url);

const tlds = new Set(['com', 'net', 'org']);
for (const file of ['tlds.dict', 'abused_tlds.dict', 'tld_names.dat'])
  for (const line of readFileSync(new URL(file, dict), 'utf8').split('\n')) {
    const t = line.trim().toLowerCase();
    if (!t || t.startsWith('/') || t.startsWith('#')) continue;
    tlds.add(t.replace(/^[*!.]+/, '').split('.').pop());
  }

const portFor = (tld) => (tld === 'com' || tld === 'net' ? BASE + 1 : BASE + 2 + ([...tld].reduce((a, c) => a + c.charCodeAt(0), 0) % REGISTRIES));
const groups = new Map();
for (const t of tlds) {
  const p = portFor(t);
  if (!groups.has(p)) groups.set(p, []);
  groups.get(p).push(t);
}
const bootstrap = {
  version: '1.0',
  publication: new Date().toISOString(),
  services: [...groups].map(([p, list]) => [list, [`http://127.0.0.1:${p}/`]]),
};

const stats = { lookups: 0 };
const domainJson = (name) => ({
  objectClassName: 'domain',
  ldhName: name,
  status: ['client transfer prohibited'],
  events: [
    { eventAction: 'registration', eventDate: new Date(Date.now() - (5 + (name.length % 400)) * 86_400_000).toISOString() },
    { eventAction: 'expiration', eventDate: new Date(Date.now() + 200 * 86_400_000).toISOString() },
  ],
  nameservers: [{ objectClassName: 'nameserver', ldhName: 'ns1.stub-registrar.test' }],
  entities: [
    {
      objectClassName: 'entity',
      roles: ['registrar'],
      vcardArray: ['vcard', [['version', {}, 'text', '4.0'], ['fn', {}, 'text', 'Stub Registrar LLC']]],
      entities: [
        {
          objectClassName: 'entity',
          roles: ['abuse'],
          vcardArray: ['vcard', [['version', {}, 'text', '4.0'], ['email', {}, 'text', 'abuse@stub-registrar.test']]],
        },
      ],
    },
  ],
});

function handler(req, res) {
  const url = new URL(req.url, 'http://stub');
  if (url.pathname === '/bootstrap') {
    res.writeHead(200, { 'content-type': 'application/json' });
    return res.end(JSON.stringify(bootstrap));
  }
  const m = /^\/domain\/(.+)$/.exec(url.pathname);
  if (!m) return res.writeHead(404).end();
  stats.lookups++;
  setTimeout(() => {
    res.writeHead(200, { 'content-type': 'application/rdap+json' });
    res.end(JSON.stringify(domainJson(decodeURIComponent(m[1]).toLowerCase())));
  }, LATENCY * (0.5 + Math.random()));
}

for (const port of [BASE, ...groups.keys()]) createServer(handler).listen(port, '127.0.0.1');
console.log(`rdap-stub: bootstrap http://127.0.0.1:${BASE}/bootstrap — ${tlds.size} TLDs over ${groups.size} registries (.com/.net → :${BASE + 1})`);
setInterval(() => console.log(`rdap-stub ${new Date().toISOString()} lookups=${stats.lookups}`), 60_000).unref();
