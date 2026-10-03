import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../../database/prisma.service.js';

export type NodeKind =
  'lookalike' | 'brand' | 'ip' | 'nameserver' | 'mailserver' | 'registrar';
export type EdgeKind =
  | 'imitates'
  | 'resolves-to'
  | 'uses-nameserver'
  | 'mail-via'
  | 'registered-with';

export interface GraphNode {
  id: string;
  kind: NodeKind;
  label: string;
  /** Look-alike nodes: risk + status for colouring; infrastructure nodes: how many look-alikes use it. */
  riskScore?: number;
  threatLevel?: string;
  status?: string;
  scannedDomainId?: string;
  sharedBy?: number;
  /** The look-alike the graph is centred on. */
  focus?: boolean;
}

export interface GraphEdge {
  source: string;
  target: string;
  kind: EdgeKind;
}

export interface TimelineEntry {
  at: string;
  kind:
    | 'discovered'
    | 'whois'
    | 'screenshot'
    | 'score'
    | 'review'
    | 'alert'
    | 'last-seen';
  title: string;
  detail: string | null;
  tone: 'neutral' | 'info' | 'success' | 'warning' | 'danger';
}

/** Neighbours per infrastructure node; the total is still reported in `sharedBy`. */
export const NEIGHBOUR_LIMIT = 12;

/**
 * Read model behind the console's investigation views (OpenCTI-style): the infrastructure a
 * look-alike uses and which other look-alikes share it, and a unified activity timeline.
 * Reads only, across tables (no writes, no events).
 */
@Injectable()
export class InsightsService {
  constructor(private readonly prisma: PrismaService) {}

  private async lookalike(id: string) {
    const d = await this.prisma.scannedDomain.findFirst({
      where: { id, deletedAt: null },
      select: {
        id: true,
        domain: true,
        status: true,
        riskScore: true,
        threatLevel: true,
        dnsA: true,
        dnsNs: true,
        dnsMx: true,
        firstSeenAt: true,
        lastSeenAt: true,
        fuzzer: true,
        originalDomain: { select: { id: true, domain: true } },
      },
    });
    if (!d) throw new NotFoundException(`Scanned domain ${id} not found`);
    return d;
  }

  async related(
    id: string,
  ): Promise<{ nodes: GraphNode[]; edges: GraphEdge[] }> {
    const d = await this.lookalike(id);
    const nodes = new Map<string, GraphNode>();
    const edges: GraphEdge[] = [];
    const add = (n: GraphNode) => {
      if (!nodes.has(n.id)) nodes.set(n.id, n);
      return n.id;
    };
    const look = (
      x: {
        id: string;
        domain: string;
        riskScore: number;
        threatLevel: string;
        status: string;
      },
      focus = false,
    ) =>
      add({
        id: `lookalike:${x.id}`,
        kind: 'lookalike',
        label: x.domain,
        riskScore: x.riskScore,
        threatLevel: x.threatLevel,
        status: x.status,
        scannedDomainId: x.id,
        focus,
      });

    const center = look(d, true);
    edges.push({
      source: center,
      target: add({
        id: `brand:${d.originalDomain.id}`,
        kind: 'brand',
        label: d.originalDomain.domain,
      }),
      kind: 'imitates',
    });

    const pivots: {
      kind: 'ip' | 'nameserver' | 'mailserver';
      edge: EdgeKind;
      values: string[];
      column: 'dnsA' | 'dnsNs' | 'dnsMx';
    }[] = [
      {
        kind: 'ip',
        edge: 'resolves-to',
        values: (d.dnsA ?? []).slice(0, 5),
        column: 'dnsA',
      },
      {
        kind: 'nameserver',
        edge: 'uses-nameserver',
        values: (d.dnsNs ?? []).slice(0, 4),
        column: 'dnsNs',
      },
      {
        kind: 'mailserver',
        edge: 'mail-via',
        values: (d.dnsMx ?? []).slice(0, 3),
        column: 'dnsMx',
      },
    ];
    for (const p of pivots) {
      for (const value of p.values) {
        const where = {
          deletedAt: null,
          id: { not: d.id },
          [p.column]: { has: value },
        };
        const [others, total] = await Promise.all([
          this.prisma.scannedDomain.findMany({
            where,
            orderBy: { riskScore: 'desc' },
            take: NEIGHBOUR_LIMIT,
            select: {
              id: true,
              domain: true,
              riskScore: true,
              threatLevel: true,
              status: true,
            },
          }),
          this.prisma.scannedDomain.count({ where }),
        ]);
        const node = add({
          id: `${p.kind}:${value}`,
          kind: p.kind,
          label: value,
          sharedBy: total + 1,
        });
        edges.push({ source: center, target: node, kind: p.edge });
        for (const o of others)
          edges.push({ source: look(o), target: node, kind: p.edge });
      }
    }

    const whois = await this.prisma.whoisInformation.findFirst({
      where: { scannedDomainId: d.id, registrar: { not: null } },
      orderBy: { fetchedAt: 'desc' },
      select: { registrar: true },
    });
    if (whois?.registrar) {
      const node = add({
        id: `registrar:${whois.registrar.toLowerCase()}`,
        kind: 'registrar',
        label: whois.registrar,
      });
      edges.push({ source: center, target: node, kind: 'registered-with' });
    }

    // De-duplicate edges (a neighbour can share several pivots).
    const seen = new Set<string>();
    return {
      nodes: [...nodes.values()],
      edges: edges.filter((e) => {
        const k = `${e.source}|${e.target}|${e.kind}`;
        return seen.has(k) ? false : (seen.add(k), true);
      }),
    };
  }

  async timeline(id: string, limit = 100): Promise<TimelineEntry[]> {
    const d = await this.lookalike(id);
    const [whois, shots, scores, reviews, alerts] = await Promise.all([
      this.prisma.whoisInformation.findMany({
        where: { scannedDomainId: id },
        orderBy: { fetchedAt: 'desc' },
        take: 20,
        select: {
          fetchedAt: true,
          source: true,
          registrar: true,
          parseSucceeded: true,
        },
      }),
      this.prisma.screenshot.findMany({
        where: { scannedDomainId: id },
        orderBy: { createdAt: 'desc' },
        take: 20,
        select: {
          createdAt: true,
          status: true,
          pageTitle: true,
          httpStatus: true,
          errorMessage: true,
        },
      }),
      this.prisma.analytics.findMany({
        where: { scannedDomainId: id },
        orderBy: { computedAt: 'desc' },
        take: 30,
        select: { computedAt: true, totalScore: true, threatLevel: true },
      }),
      this.prisma.review.findMany({
        where: { scannedDomainId: id },
        orderBy: { createdAt: 'desc' },
        take: 30,
        select: {
          createdAt: true,
          verdict: true,
          reviewer: true,
          previousStatus: true,
          newStatus: true,
          notes: true,
        },
      }),
      this.prisma.alertDelivery.findMany({
        where: { scannedDomainId: id },
        orderBy: { createdAt: 'desc' },
        take: 20,
        select: {
          createdAt: true,
          eventType: true,
          status: true,
          channel: { select: { name: true } },
        },
      }),
    ]);

    const out: TimelineEntry[] = [
      {
        at: d.firstSeenAt.toISOString(),
        kind: 'discovered',
        title: d.fuzzer.startsWith('ct:')
          ? 'Found in Certificate Transparency'
          : 'Discovered by scan',
        detail: `Technique: ${d.fuzzer}`,
        tone: 'info',
      },
    ];
    if (d.lastSeenAt.getTime() - d.firstSeenAt.getTime() > 60_000)
      out.push({
        at: d.lastSeenAt.toISOString(),
        kind: 'last-seen',
        title: 'Last seen resolving',
        detail: null,
        tone: 'neutral',
      });
    for (const w of whois)
      out.push({
        at: w.fetchedAt.toISOString(),
        kind: 'whois',
        title: `Registration data (${w.source})`,
        detail: w.parseSucceeded
          ? (w.registrar ?? 'Registrar unknown')
          : 'No registration data',
        tone: 'neutral',
      });
    for (const s of shots)
      out.push({
        at: s.createdAt.toISOString(),
        kind: 'screenshot',
        title: s.status === 'CAPTURED' ? 'Page captured' : 'Capture failed',
        detail:
          s.status === 'CAPTURED'
            ? `${s.pageTitle || 'Untitled'} · HTTP ${s.httpStatus ?? '—'}`
            : s.errorMessage,
        tone: s.status === 'CAPTURED' ? 'neutral' : 'warning',
      });
    // Scores: only changes of band (and the first), not every identical rescore.
    let prevLevel: string | null = null;
    for (const a of [...scores].reverse()) {
      if (a.threatLevel !== prevLevel)
        out.push({
          at: a.computedAt.toISOString(),
          kind: 'score',
          title: prevLevel
            ? `Risk changed to ${a.threatLevel.replace('_', ' ').toLowerCase()}`
            : `Scored ${a.threatLevel.replace('_', ' ').toLowerCase()}`,
          detail: `Score ${a.totalScore}`,
          tone:
            a.threatLevel === 'HIGH_RISK'
              ? 'danger'
              : a.threatLevel === 'MEDIUM_RISK'
                ? 'warning'
                : 'neutral',
        });
      prevLevel = a.threatLevel;
    }
    for (const r of reviews)
      out.push({
        at: r.createdAt.toISOString(),
        kind: 'review',
        title: `Reviewed as ${r.verdict.replace('_', ' ').toLowerCase()} by ${r.reviewer}`,
        detail: [`${r.previousStatus} → ${r.newStatus}`, r.notes]
          .filter(Boolean)
          .join(' · '),
        tone:
          r.verdict === 'MALICIOUS'
            ? 'danger'
            : r.verdict === 'BENIGN' || r.verdict === 'FALSE_POSITIVE'
              ? 'success'
              : 'info',
      });
    for (const a of alerts)
      out.push({
        at: a.createdAt.toISOString(),
        kind: 'alert',
        title: `Alert sent to ${a.channel.name}`,
        detail: `${a.eventType.replace('_', ' ').toLowerCase()} · ${a.status.toLowerCase()}`,
        tone: a.status === 'FAILED' ? 'warning' : 'neutral',
      });
    return out.sort((x, y) => y.at.localeCompare(x.at)).slice(0, limit);
  }
}
