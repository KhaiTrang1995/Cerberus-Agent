/**
 * The settings fingerprint a queued job is compared against, computed the way
 * the dispatcher computes it.
 *
 * `settingsFingerprint` hashes the Project row, but two inputs of the real hash
 * are not on the row: TruffleHog's per-source profile and the auth profile,
 * which is a relation. Enqueue, dispatch and re-confirm each fold both in. A
 * fourth caller that hashed the row alone - the MCP report of which queued jobs
 * a settings write parked - disagreed with the dispatcher on every auth-aware
 * kind, so it reported every queued full and partial recon as parked.
 *
 * Kept apart from `jobQueue.ts` because that module is pure and the extras read
 * the database.
 */
import { settingsFingerprint } from '@/lib/jobQueue'
import { resolveTrufflehogFingerprintExtra } from '@/lib/trufflehogStart'
import { authProfileFingerprintExtra } from '@/lib/authProfileFingerprint'

export interface FingerprintedJob {
  kind: string
  projectId: string
  payload?: unknown
}

export async function currentFingerprintFor(
  job: FingerprintedJob,
  row: Record<string, unknown>,
): Promise<string> {
  const payload = (job.payload && typeof job.payload === 'object' ? job.payload : {}) as Record<string, unknown>
  return settingsFingerprint(job.kind, row, {
    ...(await resolveTrufflehogFingerprintExtra(job.kind, job.projectId, payload)),
    ...(await authProfileFingerprintExtra(job.kind, job.projectId)),
  })
}
