import {
  DomainStatus,
  ReviewVerdict,
} from '../../database/generated/prisma/enums.js';

/** The look-alike status a review verdict results in. */
export const VERDICT_STATUS: Record<ReviewVerdict, DomainStatus> = {
  [ReviewVerdict.MALICIOUS]: DomainStatus.CONFIRMED_THREAT,
  [ReviewVerdict.SUSPICIOUS]: DomainStatus.UNDER_REVIEW,
  [ReviewVerdict.NEEDS_INFO]: DomainStatus.UNDER_REVIEW,
  [ReviewVerdict.BENIGN]: DomainStatus.ACTIVE,
  [ReviewVerdict.FALSE_POSITIVE]: DomainStatus.FALSE_POSITIVE,
};
