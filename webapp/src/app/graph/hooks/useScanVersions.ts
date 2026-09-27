import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useCallback } from 'react'

/** One row of the project's scan timeline. */
export interface ScanVersionSummary {
  id: string
  seq: number
  label: string
  /** True for the version that IS the live Neo4j graph (the active version). */
  isCurrent: boolean
  pinned: boolean
  nodeCount: number | null
  linkCount: number | null
  createdAt: string
  snapshotBytes: number
  /** Finding sources the run behind this version could not fully re-check
   *  (circuit breakers). null = unknown/complete, N>0 = partial. */
  degradedSources?: number | null
  /** False for the current version and for versions with no restorable bytes. */
  activatable: boolean
}

export interface ScanVersionsResponse {
  versions: ScanVersionSummary[]
  /** True while this project's live graph is being swapped by an activation. */
  activating: boolean
}

async function fetchVersions(projectId: string): Promise<ScanVersionsResponse> {
  const res = await fetch(`/api/projects/${projectId}/versions`)
  if (!res.ok) throw new Error('Failed to load scan versions')
  return res.json()
}

export function useScanVersions(projectId: string | null) {
  const queryClient = useQueryClient()

  const query = useQuery({
    queryKey: ['scanVersions', projectId],
    queryFn: () => fetchVersions(projectId!),
    enabled: !!projectId,
    staleTime: 15000,
  })

  const refresh = useCallback(() => {
    if (projectId) queryClient.invalidateQueries({ queryKey: ['scanVersions', projectId] })
  }, [projectId, queryClient])

  const versions = query.data?.versions ?? []
  return {
    ...query,
    versions,
    activating: query.data?.activating ?? false,
    currentVersion: versions.find(v => v.isCurrent) ?? null,
    refresh,
  }
}
