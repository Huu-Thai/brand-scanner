// Authoritative-looking DNS stub for load tests (UDP). Never forwards anything to the internet.
// A name is "registered" when FNV-1a(name) % 1000 < REGISTERED_PER_MILLE (deterministic per name).
//   registered  → NS / A (127.0.0.1, TTL 300) / MX for half of them / AAAA empty
//   otherwise   → NXDOMAIN for every type (as are _dmarc.*, Spamhaus and other helper lookups)
// Latency: LATENCY_MS ± JITTER_MS per answer, to mimic a nearby recursive resolver.
import dgram from 'node:dgram';

const PORT = Number(process.env.DNS_STUB_PORT ?? 5354);
const PER_MILLE = Number(process.env.REGISTERED_PER_MILLE ?? 15);
const LATENCY = Number(process.env.LATENCY_MS ?? 25);
const JITTER = Number(process.env.JITTER_MS ?? 15);

const fnv = (s) => {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) h = Math.imul(h ^ s.charCodeAt(i), 0x01000193) >>> 0;
  return h;
};
export const isRegistered = (name) =>
  !name.startsWith('_') && !name.includes('spamhaus') && name.split('.').length >= 2 && fnv(name) % 1000 < PER_MILLE;

function readName(buf, off) {
  const labels = [];
  for (;;) {
    const len = buf[off++];
    if (len === 0) break;
    labels.push(buf.toString('latin1', off, off + len));
    off += len;
  }
  return { name: labels.join('.').toLowerCase(), end: off };
}

function encodeName(name) {
  const parts = name.split('.').filter(Boolean);
  return Buffer.concat([...parts.map((p) => Buffer.concat([Buffer.from([p.length]), Buffer.from(p)])), Buffer.from([0])]);
}

function rr(type, ttl, rdata) {
  const h = Buffer.alloc(12);
  h.writeUInt16BE(0xc00c, 0); // pointer to the question name
  h.writeUInt16BE(type, 2);
  h.writeUInt16BE(1, 4);
  h.writeUInt32BE(ttl, 6);
  h.writeUInt16BE(rdata.length, 10);
  return Buffer.concat([h, rdata]);
}

const stats = { queries: 0, registered: 0 };
const server = dgram.createSocket('udp4');
server.on('message', (msg, rinfo) => {
  stats.queries++;
  const { name, end } = readName(msg, 12);
  const qtype = msg.readUInt16BE(end);
  const question = msg.subarray(12, end + 4);
  const reg = isRegistered(name);
  const answers = [];
  if (reg) {
    if (qtype === 1) answers.push(rr(1, 300, Buffer.from([127, 0, 0, 1])));
    if (qtype === 2) answers.push(rr(2, 3600, encodeName('ns1.stub-registrar.test')));
    if (qtype === 15 && fnv(`mx:${name}`) % 2 === 0) {
      const pref = Buffer.alloc(2);
      pref.writeUInt16BE(10, 0);
      answers.push(rr(15, 3600, Buffer.concat([pref, encodeName(`mx.${name}`)])));
    }
  }
  const header = Buffer.alloc(12);
  header.writeUInt16BE(msg.readUInt16BE(0), 0); // id
  const rd = msg.readUInt16BE(2) & 0x0100;
  header.writeUInt16BE(0x8000 | 0x0400 | rd | 0x0080 | (reg ? 0 : 3), 2); // QR AA RD RA rcode
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(answers.length, 6);
  const reply = Buffer.concat([header, question, ...answers]);
  const delay = Math.max(0, LATENCY + (Math.random() * 2 - 1) * JITTER);
  setTimeout(() => server.send(reply, rinfo.port, rinfo.address), delay);
});
server.bind(PORT, '127.0.0.1', () =>
  console.log(`dns-stub on 127.0.0.1:${PORT} (registered ${PER_MILLE}/1000, latency ${LATENCY}±${JITTER} ms)`),
);
setInterval(() => console.log(`dns-stub ${new Date().toISOString()} queries=${stats.queries}`), 60_000).unref();
