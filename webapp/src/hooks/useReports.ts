/**
 * useReports Hook
 *
 * TanStack Query hooks for fetching, generating, and deleting reports.
 * Supports both project-specific and all-projects modes.
 */

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useFeatureModelGate, type FeatureModelGateApi } from '@/components/shared/FeatureModelGate'
import { featureModelMessage, readFeatureModelCode } from '@/lib/llmFeatures'

export interface ReportMeta {
  id: string
  projectId: string
  title: string
  filename: string
  fileSize: number
  format: string
  metrics: {
    riskScore?: number
    riskLabel?: string
    totalVulnerabilities?: number
    totalCves?: number
    criticalCount?: number
    highCount?: number
    mediumCount?: number
    lowCount?: number
    cveCriticalCount?: number
    cveHighCount?: number
    cveMediumCount?: number
    cveLowCount?: number
    totalRemediations?: number
    exploitableCount?: number
  }
  hasNarratives: boolean
  createdAt: string
  project?: {
    id: string
    name: string
    targetDomain?: string
  }
}

const REPORTS_KEY = 'reports'
const ALL_REPORTS_KEY = 'all-reports'

async function fetchReports(projectId: string): Promise<ReportMeta[]> {
  const res = await fetch(`/api/projects/${projectId}/reports`)
  if (!res.ok) throw new Error('Failed to fetch reports')
  return res.json()
}

async function fetchAllReports(): Promise<ReportMeta[]> {
  const res = await fetch('/api/reports')
  if (!res.ok) throw new Error('Failed to fetch reports')
  return res.json()
}

type ReportGate = Pick<FeatureModelGateApi, 'ensureFeatureModel' | 'fetchWithFeatureModel'>

/**
 * Generate one report. Resolves null when the user cancels the first model
 * prompt: nothing was sent, so there is no failure to show.
 */
async function generateReport(projectId: string, gate: ReportGate): Promise<ReportMeta | null> {
  // The narratives run on the user's own "Report narratives" model, which the
  // route reads itself; this only makes sure one is saved.
  if (!(await gate.ensureFeatureModel('report_narratives'))) return null
  const res = await gate.fetchWithFeatureModel('report_narratives',
    () => fetch(`/api/projects/${projectId}/reports`, { method: 'POST' }))
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    const code = readFeatureModelCode(body)
    throw new Error(code
      ? featureModelMessage(code, typeof body.model === 'string' ? body.model : undefined)
      : body.error || 'Report generation failed')
  }
  return res.json()
}

async function deleteReport(projectId: string, reportId: string): Promise<void> {
  const res = await fetch(`/api/projects/${projectId}/reports/${reportId}`, { method: 'DELETE' })
  if (!res.ok) throw new Error('Failed to delete report')
}

/** Hook for project-specific reports */
export function useReports(projectId: string, enabled = true) {
  const queryClient = useQueryClient()
  const gate = useFeatureModelGate()

  const query = useQuery({
    queryKey: [REPORTS_KEY, projectId],
    queryFn: () => fetchReports(projectId),
    enabled: enabled && !!projectId,
    staleTime: 30_000,
  })

  const generateMutation = useMutation({
    mutationFn: () => generateReport(projectId, gate),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [REPORTS_KEY, projectId] })
      queryClient.invalidateQueries({ queryKey: [ALL_REPORTS_KEY] })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (reportId: string) => deleteReport(projectId, reportId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [REPORTS_KEY, projectId] })
      queryClient.invalidateQueries({ queryKey: [ALL_REPORTS_KEY] })
    },
  })

  return {
    reports: query.data ?? [],
    isLoading: query.isLoading,
    error: query.error,
    generate: generateMutation.mutateAsync,
    isGenerating: generateMutation.isPending,
    generateError: generateMutation.error,
    deleteReport: deleteMutation.mutate,
    isDeleting: deleteMutation.isPending,
  }
}

/** Hook for all-projects reports listing */
export function useAllReports() {
  const queryClient = useQueryClient()
  const gate = useFeatureModelGate()

  const query = useQuery({
    queryKey: [ALL_REPORTS_KEY],
    queryFn: fetchAllReports,
    staleTime: 30_000,
  })

  const deleteMutation = useMutation({
    mutationFn: ({ projectId, reportId }: { projectId: string; reportId: string }) =>
      deleteReport(projectId, reportId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [ALL_REPORTS_KEY] })
    },
  })

  const generateMutation = useMutation({
    mutationFn: (projectId: string) => generateReport(projectId, gate),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [ALL_REPORTS_KEY] })
    },
  })

  return {
    reports: query.data ?? [],
    isLoading: query.isLoading,
    error: query.error,
    generate: generateMutation.mutateAsync,
    isGenerating: generateMutation.isPending,
    generateError: generateMutation.error,
    deleteReport: deleteMutation.mutate,
    isDeleting: deleteMutation.isPending,
  }
}
