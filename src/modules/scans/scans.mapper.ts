import type { ScanModel } from '../../database/generated/prisma/models.js';
import type { ScanDto } from './dto/scan.dto.js';

export function toScanDto(row: ScanModel): ScanDto {
  const progressPercent =
    row.permutationsTotal > 0
      ? Math.min(
          100,
          Math.round((row.resolvedCount / row.permutationsTotal) * 1000) / 10,
        )
      : row.status === 'COMPLETED'
        ? 100
        : 0;
  return {
    id: row.id,
    originalDomainId: row.originalDomainId,
    status: row.status,
    triggeredBy: row.triggeredBy,
    options: (row.options ?? {}) as ScanDto['options'],
    permutationsTotal: row.permutationsTotal,
    resolvedCount: row.resolvedCount,
    registeredCount: row.registeredCount,
    newCount: row.newCount,
    failedCount: row.failedCount,
    progressPercent,
    errorMessage: row.errorMessage,
    startedAt: row.startedAt,
    finishedAt: row.finishedAt,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}
