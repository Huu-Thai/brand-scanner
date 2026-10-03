import { AsyncLocalStorage } from 'node:async_hooks';

/** Correlation fields attached to every log line emitted while handling a request or job. */
export interface RequestContext {
  requestId?: string;
  jobId?: string;
  queue?: string;
  scanId?: string;
}

const storage = new AsyncLocalStorage<RequestContext>();

export const requestContext = {
  run<T>(context: RequestContext, fn: () => T): T {
    return storage.run({ ...context }, fn);
  },
  get(): RequestContext | undefined {
    return storage.getStore();
  },
  /** Adds fields to the current context (e.g. scanId once a job has loaded it). */
  set(patch: Partial<RequestContext>): void {
    const store = storage.getStore();
    if (store) Object.assign(store, patch);
  },
};
