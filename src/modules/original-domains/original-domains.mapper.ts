import type { OriginalDomainModel } from '../../database/generated/prisma/models.js';
import type { OriginalDomainDto } from './dto/original-domain.dto.js';
import type { OriginalDomainSnapshot } from './events/original-domain.events.js';

export function toOriginalDomainDto(
  row: OriginalDomainModel,
): OriginalDomainDto {
  return {
    id: row.id,
    domain: row.domain,
    unicodeDomain: row.unicodeDomain,
    label: row.label,
    isActive: row.isActive,
    scanSchedule: row.scanSchedule,
    scanOptions: (row.scanOptions ?? {}) as OriginalDomainDto['scanOptions'],
    lastScannedAt: row.lastScannedAt,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

export function toSnapshot(row: OriginalDomainModel): OriginalDomainSnapshot {
  return {
    id: row.id,
    domain: row.domain,
    isActive: row.isActive,
    scanSchedule: row.scanSchedule,
  };
}
