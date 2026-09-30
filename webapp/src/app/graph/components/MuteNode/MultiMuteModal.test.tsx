/**
 * Multi mute's modal, driven from its button inside the graph page's provider.
 *
 * What is pinned: the model gate (before the search, and on model_required);
 * the groups in the order the server gave; one selection per finding across
 * groups; which actions confirm; the writes (keys, seed, concept, chunks of
 * 500 under one batch); the activity bar's Undo and its retry after a 409;
 * every error code; and the one toast on close.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor, within, act } from '@testing-library/react'
import {
  GATE_USER, jsonResponse, pickInGate, stubGateFetch, type GateFetchStub,
} from '@/components/shared/featureModelGate.testUtils'

const mockDangerConfirm = vi.fn()
const mockAddToast = vi.fn()

vi.mock('@/components/ui', () => ({
  useAlertModal: () => ({ alertError: vi.fn(), dangerConfirm: mockDangerConfirm }),
  useToast: () => ({ success: vi.fn(), error: vi.fn(), warning: vi.fn(), info: vi.fn(), addToast: mockAddToast }),
}))
vi.mock('@/providers/ProjectProvider', () => ({
  useProject: () => ({ userId: GATE_USER }),
  useOptionalProject: () => ({ userId: GATE_USER }),
}))

import { MultiMuteButton, MuteNodeProvider } from './index'
import type { MultiMuteMember, SuggestResult } from './multiMuteModel'

const SUGGEST = '/api/triage/multi-mute/suggest'
const APPLY = '/api/triage/multi-mute/apply'
const UNMUTE = '/api/triage/unmute'
const BATCH = 'mm-3f9a2c1d'

function member(key: string, over: Partial<MultiMuteMember> = {}): MultiMuteMember {
  return {
    key, node_id: String(100 + key.length), name: `finding ${key}`, host: 'host-b.example', severity: 'low',
    verdict: 'match', why: 'the same version banner', quote: 'Server: nginx', quote_verified: true,
    checked: true, ai_only: false, ...over,
  }
}

function suggestion(over: Partial<SuggestResult> = {}): SuggestResult {
  return {
    status: 'ok', batch_id: BATCH, prompt_version: 'multi-mute-v1', model: 'claude-haiku-4-5',
    seed: {
      key: 'v-seed', node_id: '42', label: 'Vulnerability', kind: 'Nuclei', name: 'Nginx version disclosure',
      host: 'host-a.example', severity: 'low', source: 'nuclei', triaged: true,
    },
    read: { reason: 'not_worth_fixing', why: 'an informational version banner', quote: '', quote_verified: false },
    pool: { total: 412, candidates: 375, excluded: { above_seed: 30, proven: 7 }, truncated: false, clusters_sent: 12 },
    groups: [
      {
        id: 'g1', concepts: ['same_low_risk'], labels: ['Same low-risk weakness'], ai: true,
        title: 'Informational tech fingerprints', why: 'All of them are version banners',
        members: [member('v-1'), member('v-2', { ai_only: true, checked: false, verdict: 'maybe' })],
        probably_not: [],
      },
      {
        id: 'g2', concepts: ['same_problem', 'same_detector'], labels: ['Same issue elsewhere', 'Same detector'],
        ai: false, title: null, why: null,
        members: [member('v-1'), member('v-3', { severity: 'high' })],
        probably_not: [member('v-4', { verdict: 'no', checked: false })],
      },
    ],
    ...over,
  }
}

type Handler = (body: Record<string, unknown>) => Response | Promise<Response>

const mutedAll: Handler = body => jsonResponse(200, {
  batchId: body.batchId,
  items: (body.keys as string[]).map(k => ({
    key: k, label: 'Vulnerability', node_id: '1', name: k, severity: 'low', outcome: 'muted',
  })),
  notFound: [], workItemsAffected: 0, triageRunLive: false,
})

/** `mutedAll`, with extra fields on the answer. */
const mutedWith = (extra: Record<string, unknown>): Handler => async body =>
  jsonResponse(200, { ...(await (await mutedAll(body)).json()), ...extra })

const unmutedAll: Handler = body => jsonResponse(200, {
  unmuted: (body.keys as string[]).length,
  items: (body.keys as string[]).map(k => ({ key: k, label: 'Vulnerability', muted_by: GATE_USER })),
  exempted: 0, skipped: [],
})

let suggestRoute: ReturnType<typeof vi.fn<Handler>>
let applyRoute: ReturnType<typeof vi.fn<Handler>>
let unmuteRoute: ReturnType<typeof vi.fn<Handler>>
let stub: GateFetchStub
const onGraphChanged = vi.fn()
const onViewMuted = vi.fn()
const onOpenMuteRules = vi.fn()
const onSeedMuted = vi.fn()
const onMuted = vi.fn()

function serve(saved: Record<string, string> = { multi_mute: 'claude-haiku-4-5' }) {
  stub = stubGateFetch(saved, (url, init) => {
    const body = init?.body ? JSON.parse(init.body as string) : {}
    if (url === SUGGEST) return suggestRoute(body)
    if (url === APPLY) return applyRoute(body)
    if (url === UNMUTE) return unmuteRoute(body)
    return jsonResponse(404, { error: `unexpected ${url}` })
  })
}

beforeEach(() => {
  suggestRoute = vi.fn<Handler>(() => jsonResponse(200, suggestion()))
  applyRoute = vi.fn<Handler>(mutedAll)
  unmuteRoute = vi.fn<Handler>(unmutedAll)
  mockDangerConfirm.mockResolvedValue(true)
  serve()
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.clearAllMocks()
})

function open(seed = { name: 'Nginx version disclosure', nodeId: 'v-seed', label: 'Vulnerability' }) {
  render(
    <MuteNodeProvider
      projectId="p1" readOnly={false}
      onViewMuted={onViewMuted} onGraphChanged={onGraphChanged} onOpenMuteRules={onOpenMuteRules}
    >
      <MultiMuteButton seed={seed} onSeedMuted={onSeedMuted} onMuted={onMuted} />
    </MuteNodeProvider>,
  )
  fireEvent.click(screen.getByRole('button', { name: 'Multi mute' }))
}

async function openResults() {
  open()
  await screen.findByText(/Findings like/)
}

const sentTo = (route: ReturnType<typeof vi.fn<Handler>>, i = 0) => route.mock.calls[i][0]
const group = (name: RegExp | string) => screen.getByRole('region', { name })
const selectBoxes = (name: string) => screen.getAllByRole('checkbox', { name: `Select ${name}` }) as HTMLInputElement[]
const rowOf = (name: string) => selectBoxes(name)[0].closest('tr')!
const muteSelected = (g: HTMLElement) => within(g).getByRole('button', { name: /^Mute \d+ selected$/ })
const muteAllButton = () => screen.getByRole('button', { name: /^Mute all selected/ })

describe('the model gate', () => {
  test('no saved model: the gate opens before any search, then it runs once', async () => {
    serve({})
    open()
    await pickInGate('Claude Haiku 4.5', 'Save and run')
    expect(await screen.findByText(/Findings like/)).toBeInTheDocument()
    expect(stub.saved).toEqual({ multi_mute: 'claude-haiku-4-5' })
    expect(suggestRoute).toHaveBeenCalledOnce()
    expect(sentTo(suggestRoute)).toEqual({ projectId: 'p1', nodeId: 'v-seed' })
  })

  test('model_required from the server opens the gate, then retries', async () => {
    suggestRoute.mockImplementationOnce(() => jsonResponse(409, {
      error: 'Choose a model for this feature first', code: 'model_required', featureId: 'multi_mute',
    }))
    open()
    await pickInGate('Claude Opus 4.6', 'Save and run')
    expect(await screen.findByText(/Findings like/)).toBeInTheDocument()
    expect(suggestRoute).toHaveBeenCalledTimes(2)
    expect(stub.saved.multi_mute).toBe('claude-opus-4-6')
  })

  test('model_unavailable opens the gate with the fixed message', async () => {
    suggestRoute.mockImplementationOnce(() => jsonResponse(503, {
      error: 'x', code: 'model_unavailable', featureId: 'multi_mute', model: 'claude-haiku-4-5',
    }))
    open()
    expect(await screen.findByText('Your model claude-haiku-4-5 could not be used')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Save and run' })).toBeInTheDocument()
  })

  test('cancelling the first gate closes Multi mute without a search', async () => {
    serve({})
    open()
    await screen.findByRole('button', { name: 'Save and run' })
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(suggestRoute).not.toHaveBeenCalled()
  })

  test('"Change" re-opens the gate inline and re-runs on the new model', async () => {
    await openResults()
    expect(screen.getByText('claude-haiku-4-5')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Change the Multi mute model' }))
    await pickInGate('Claude Opus 4.6', 'Save and run')
    await waitFor(() => expect(suggestRoute).toHaveBeenCalledTimes(2))
    expect(stub.saved.multi_mute).toBe('claude-opus-4-6')
  })
})

describe('loading', () => {
  test('says which model it asks, and Cancel drops a late answer', async () => {
    let answer!: (r: Response) => void
    suggestRoute.mockImplementationOnce(() => new Promise<Response>(r => { answer = r }))
    open()
    expect(await screen.findByText(/Asking claude-haiku-4-5…/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    answer(jsonResponse(200, suggestion()))
    await new Promise(r => setTimeout(r, 20))
    expect(screen.queryByText(/Findings like/)).toBeNull()
  })

  test('a re-run names the pool it compares with', async () => {
    await openResults()
    let answer!: (r: Response) => void
    suggestRoute.mockImplementationOnce(() => new Promise<Response>(r => { answer = r }))
    fireEvent.click(screen.getByRole('button', { name: 'Change the Multi mute model' }))
    await pickInGate('Claude Opus 4.6', 'Save and run')
    expect(await screen.findByText('Comparing with 412 Nuclei findings. Asking claude-opus-4-6…')).toBeInTheDocument()
    answer(jsonResponse(200, suggestion()))
  })
})

describe('the results', () => {
  test('the seed, the AI read and the pool, with model text marked as AI', async () => {
    await openResults()
    expect(screen.getByText('Findings like “Nginx version disclosure”')).toBeInTheDocument()
    expect(screen.getByText('Nuclei · low · host-a.example')).toBeInTheDocument()
    expect(screen.getByText('AI read: not worth fixing, an informational version banner')).toBeInTheDocument()
    expect(screen.getAllByText('AI suggestion').length).toBeGreaterThan(0)
    expect(screen.getByText(/Compared with 412 Nuclei findings/)).toHaveTextContent('37 left out')
    fireEvent.click(screen.getByRole('button', { name: /why/ }))
    const why = screen.getByRole('list', { name: 'Why findings were left out' })
    expect(why).toHaveTextContent('30 higher level than this finding')
    expect(why).toHaveTextContent('7 proven')
    expect(screen.queryByText(/Run triage for better suggestions/)).toBeNull()
  })

  test('an untriaged seed asks for a triage run', async () => {
    suggestRoute.mockImplementationOnce(() => jsonResponse(200, suggestion({
      seed: { ...suggestion().seed, triaged: false },
    })))
    await openResults()
    expect(screen.getByText(/Run triage for better suggestions/)).toBeInTheDocument()
  })

  test('groups keep the server\'s order, badged exact or AI', async () => {
    await openResults()
    const regions = screen.getAllByRole('region').map(r => r.getAttribute('aria-label'))
    expect(regions).toEqual(['Informational tech fingerprints', 'Same issue elsewhere · Same detector'])
    expect(within(group('Informational tech fingerprints')).getByTitle(/Grouped by the model alone/))
      .toHaveTextContent('AI suggestion')
    expect(within(group(/Same issue elsewhere/)).getByText('exact')).toBeInTheDocument()
    expect(within(group(/Same issue elsewhere/)).queryByText('AI suggestion')).toBeNull()
  })

  test('model text is plain text, with bidi and zero-width characters stripped', async () => {
    suggestRoute.mockImplementationOnce(() => jsonResponse(200, suggestion({
      groups: [{
        ...suggestion().groups[0], title: 'Banners‮<b>x</b>​',
      }],
    })))
    await openResults()
    expect(screen.getByRole('region', { name: 'Banners<b>x</b>' })).toBeInTheDocument()
    expect(document.querySelector('b')).toBeNull()
  })

  test('the verdict badge carries the model\'s why and the verified quote as an AI suggestion', async () => {
    await openResults()
    const badge = within(rowOf('finding v-1')).getByText('match')
    expect(badge.getAttribute('title')).toBe(
      'AI suggestion\nthe same version banner\nQuote (verified in the evidence): "Server: nginx"')
  })

  test('one selection per finding, shared across the groups it is in', async () => {
    await openResults()
    fireEvent.click(within(group(/Same issue elsewhere/)).getByRole('button', { name: /Same issue elsewhere/ }))
    const boxes = selectBoxes('finding v-1')
    expect(boxes).toHaveLength(2)
    expect(boxes.every(b => b.checked)).toBe(true)
    expect(muteSelected(group('Informational tech fingerprints'))).toHaveTextContent('Mute 1 selected')
    fireEvent.click(boxes[1])
    expect(selectBoxes('finding v-1').every(b => !b.checked)).toBe(true)
    expect(muteSelected(group('Informational tech fingerprints'))).toHaveTextContent('Mute 0 selected')
    expect(screen.getByText('1 selected in 1 group')).toBeInTheDocument()
  })

  test('code\'s pre-check is kept: maybe and "probably not" start unticked', async () => {
    await openResults()
    expect(selectBoxes('finding v-2')[0].checked).toBe(false)
    const exact = group(/Same issue elsewhere/)
    fireEvent.click(within(exact).getByRole('button', { name: /Same issue elsewhere/ }))
    fireEvent.click(within(exact).getByRole('button', { name: /Probably not \(1\)/ }))
    expect(selectBoxes('finding v-4')[0].checked).toBe(false)
  })

  test('an empty pool offers the seed alone and asks nothing', async () => {
    suggestRoute.mockImplementationOnce(() => jsonResponse(200, suggestion({
      status: 'empty_pool', read: null, groups: [],
      pool: { total: 0, candidates: 0, excluded: {}, truncated: false, clusters_sent: 0 },
    })))
    await openResults()
    expect(screen.getByText('No other Nuclei findings to compare.')).toBeInTheDocument()
    fireEvent.click(screen.getByTitle('Mute this finding alone, now'))
    await waitFor(() => expect(applyRoute).toHaveBeenCalledOnce())
    expect(sentTo(applyRoute)).toEqual({
      projectId: 'p1', batchId: BATCH, keys: ['v-seed'], includeSeed: true, concept: 'seed',
    })
  })

  test('an unreadable answer shows the exact groups, a banner, and Retry', async () => {
    suggestRoute.mockImplementationOnce(() => jsonResponse(502, suggestion({
      status: 'model_unreadable',
      read: { reason: 'unclear', why: '', quote: '', quote_verified: false },
      groups: [{ ...suggestion().groups[1], members: [member('v-3', { checked: false, verdict: null })] }],
    })))
    await openResults()
    expect(screen.getByRole('alert')).toHaveTextContent(/could not be read/)
    expect(screen.queryByText(/AI read/)).toBeNull()
    expect(selectBoxes('finding v-3')[0].checked).toBe(false)
    fireEvent.click(within(screen.getByRole('alert')).getByRole('button', { name: 'Retry' }))
    await waitFor(() => expect(suggestRoute).toHaveBeenCalledTimes(2))
  })

  test('50 rows per group, then "Show more"', async () => {
    const many = Array.from({ length: 120 }, (_, i) => member(`k${String(i).padStart(3, '0')}`))
    suggestRoute.mockImplementationOnce(() => jsonResponse(200, suggestion({
      groups: [{ ...suggestion().groups[1], members: many, probably_not: [] }],
    })))
    await openResults()
    const g = group(/Same issue elsewhere/)
    expect(within(g).getAllByRole('checkbox')).toHaveLength(50)
    fireEvent.click(within(g).getByRole('button', { name: 'Show more (70 left)' }))
    expect(within(g).getAllByRole('checkbox')).toHaveLength(100)
  })

  test('an exact group links to Mute Rules on its kind; an AI group does not', async () => {
    await openResults()
    expect(within(group('Informational tech fingerprints')).queryByText(/create a Mute Rule/)).toBeNull()
    const exact = group(/Same issue elsewhere/)
    fireEvent.click(within(exact).getByRole('button', { name: /Same issue elsewhere/ }))
    fireEvent.click(within(exact).getByRole('button', { name: 'Keep hiding new ones: create a Mute Rule' }))
    expect(onOpenMuteRules).toHaveBeenCalledWith('vuln.nuclei')
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
  })
})

describe('muting', () => {
  test('a row mutes at once, under its group\'s concept, and greys out', async () => {
    await openResults()
    fireEvent.click(within(rowOf('finding v-1')).getByRole('button', { name: 'Mute' }))
    await waitFor(() => expect(applyRoute).toHaveBeenCalledOnce())
    expect(mockDangerConfirm).not.toHaveBeenCalled()
    expect(sentTo(applyRoute)).toEqual({
      projectId: 'p1', batchId: BATCH, keys: ['v-1'], includeSeed: false, concept: 'same_low_risk',
    })
    expect(await within(rowOf('finding v-1')).findByText('Muted')).toBeInTheDocument()
    expect(selectBoxes('finding v-1')[0]).toBeDisabled()
  })

  test('a finding the server re-checked and refused says why', async () => {
    applyRoute.mockImplementationOnce(body => jsonResponse(200, {
      batchId: body.batchId, notFound: [], workItemsAffected: 0, triageRunLive: false,
      items: [{ key: 'v-1', label: 'Vulnerability', node_id: '1', name: 'v-1', severity: 'high', outcome: 'above_seed' }],
    }))
    await openResults()
    fireEvent.click(within(rowOf('finding v-1')).getByRole('button', { name: 'Mute' }))
    expect(await within(rowOf('finding v-1')).findByText('Skipped: now above this finding')).toBeInTheDocument()
    expect(screen.getByText('Nothing muted · 1 skipped')).toBeInTheDocument()
  })

  test('a group of low, exact findings mutes without a confirm', async () => {
    await openResults()
    const exact = group(/Same issue elsewhere/)
    fireEvent.click(within(exact).getByRole('button', { name: /Same issue elsewhere/ }))
    fireEvent.click(selectBoxes('finding v-3')[0])
    fireEvent.click(muteSelected(exact))
    await waitFor(() => expect(applyRoute).toHaveBeenCalledOnce())
    expect(mockDangerConfirm).not.toHaveBeenCalled()
    expect(sentTo(applyRoute)).toMatchObject({ keys: ['v-1'], includeSeed: false, concept: 'same_problem' })
  })

  test('a group holding a high or critical finding asks once', async () => {
    await openResults()
    fireEvent.click(muteSelected(group(/Same issue elsewhere/)))
    await waitFor(() => expect(mockDangerConfirm).toHaveBeenCalledOnce())
    expect(mockDangerConfirm.mock.calls[0][0]).toMatch(/^Mute 2 findings\?/)
    expect(mockDangerConfirm.mock.calls[0][0]).toContain('1 of them is high or critical.')
    await waitFor(() => expect(applyRoute).toHaveBeenCalledOnce())
    expect(sentTo(applyRoute)).toMatchObject({ keys: ['v-1', 'v-3'], concept: 'same_problem' })
  })

  test('a group holding an AI-only finding asks once, and a "no" sends nothing', async () => {
    mockDangerConfirm.mockResolvedValue(false)
    await openResults()
    fireEvent.click(selectBoxes('finding v-2')[0])
    fireEvent.click(muteSelected(group('Informational tech fingerprints')))
    await waitFor(() => expect(mockDangerConfirm).toHaveBeenCalledOnce())
    expect(mockDangerConfirm.mock.calls[0][0]).toContain('1 was suggested by the AI alone')
    await new Promise(r => setTimeout(r, 10))
    expect(applyRoute).not.toHaveBeenCalled()
  })

  test('"Mute all selected" is the union plus the seed, always confirmed with the mute wording', async () => {
    await openResults()
    expect(muteAllButton()).toHaveTextContent('Mute all selected (3)')
    fireEvent.click(muteAllButton())
    await waitFor(() => expect(applyRoute).toHaveBeenCalledOnce())
    expect(mockDangerConfirm).toHaveBeenCalledOnce()
    const [text, title, opts] = mockDangerConfirm.mock.calls[0]
    expect(text).toMatch(/^Mute 3 findings\?\n\nThey will be hidden from the graph, from reports, and from the AI agent/)
    expect(title).toBe('Multi mute')
    expect(opts).toEqual({ confirmLabel: 'Mute 3' })
    expect(sentTo(applyRoute)).toEqual({
      projectId: 'p1', batchId: BATCH, keys: ['v-seed', 'v-1', 'v-3'], includeSeed: true, concept: 'selected',
    })
  })

  test('unticking "Mute this finding too" leaves the seed out', async () => {
    await openResults()
    fireEvent.click(screen.getByRole('checkbox', { name: 'Mute this finding too' }))
    fireEvent.click(muteAllButton())
    await waitFor(() => expect(applyRoute).toHaveBeenCalledOnce())
    expect(sentTo(applyRoute)).toMatchObject({ keys: ['v-1', 'v-3'], includeSeed: false, concept: 'selected' })
  })

  test('more than 500 go in several writes under the same batch, the seed in the first', async () => {
    const many = Array.from({ length: 620 }, (_, i) => member(`k${String(i).padStart(3, '0')}`))
    suggestRoute.mockImplementationOnce(() => jsonResponse(200, suggestion({
      groups: [{ ...suggestion().groups[1], members: many, probably_not: [] }],
    })))
    await openResults()
    fireEvent.click(muteAllButton())
    await waitFor(() => expect(applyRoute).toHaveBeenCalledTimes(2))
    const [first, second] = [sentTo(applyRoute, 0), sentTo(applyRoute, 1)]
    expect((first.keys as string[])).toHaveLength(500)
    expect((first.keys as string[])[0]).toBe('v-seed')
    expect(first.includeSeed).toBe(true)
    expect((second.keys as string[])).toHaveLength(121)
    expect(second.includeSeed).toBe(false)
    expect(first.batchId).toBe(BATCH)
    expect(second.batchId).toBe(BATCH)
    expect(await screen.findByText('Muted 621')).toBeInTheDocument()
  })

  test.each([
    ['batch_expired', 409, 'This suggestion expired; run Multi mute again.'],
    ['activation_busy', 409, 'A version is being activated; try again when it finishes.'],
    ['retry', 503, 'The graph was busy and nothing more was muted; try again.'],
    ['agent_outdated', 502, 'The agent is older than the webapp: rebuild it'],
  ])('a write refused with %s says so', async (code, status, message) => {
    applyRoute.mockImplementationOnce(() => jsonResponse(status, { error: 'x', code }))
    await openResults()
    fireEvent.click(within(rowOf('finding v-1')).getByRole('button', { name: 'Mute' }))
    expect(await screen.findByText(message)).toBeInTheDocument()
    if (code === 'batch_expired') {
      fireEvent.click(screen.getByRole('button', { name: 'Run Multi mute again' }))
      await waitFor(() => expect(suggestRoute).toHaveBeenCalledTimes(2))
    }
  })
})

describe('the activity bar', () => {
  test('Undo unmutes exactly what that action muted, scoped to its batch', async () => {
    await openResults()
    fireEvent.click(muteAllButton())
    const undo = await screen.findByRole('button', { name: 'Undo' })
    expect(screen.getByText('Muted 3')).toBeInTheDocument()
    fireEvent.click(undo)
    await waitFor(() => expect(unmuteRoute).toHaveBeenCalledOnce())
    expect(sentTo(unmuteRoute)).toEqual({ projectId: 'p1', keys: ['v-seed', 'v-1', 'v-3'], undoBatch: BATCH })
    expect(await screen.findByText('· undone')).toBeInTheDocument()
    // The rows are live again, and closing now reports nothing muted.
    expect(within(rowOf('finding v-1')).getByRole('button', { name: 'Mute' })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Close' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(mockAddToast).not.toHaveBeenCalled()
    expect(onGraphChanged).not.toHaveBeenCalled()
  })

  test('an Undo refused with 409 shows why and keeps the button for a retry', async () => {
    unmuteRoute.mockImplementationOnce(() => jsonResponse(409, {
      error: 'Cannot unmute while a Mute Rules apply is running. Try again when it finishes.',
    }))
    await openResults()
    fireEvent.click(within(rowOf('finding v-1')).getByRole('button', { name: 'Mute' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Undo' }))
    expect(await screen.findByText(/Cannot unmute while a Mute Rules apply is running/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Undo' }))
    await waitFor(() => expect(unmuteRoute).toHaveBeenCalledTimes(2))
    expect(await screen.findByText('· undone')).toBeInTheDocument()
    expect(screen.queryByText(/Cannot unmute/)).toBeNull()
  })
})

describe('a re-run after the seed was muted here', () => {
  test('keeps the results and their Undo (review: seed_changed wiped them)', async () => {
    await openResults()
    fireEvent.click(screen.getByTitle('Mute this finding alone, now'))
    expect(await screen.findByRole('button', { name: 'Undo' })).toBeInTheDocument()
    suggestRoute.mockImplementationOnce(() => jsonResponse(409, { error: 'x', code: 'seed_changed' }))

    fireEvent.click(screen.getByRole('button', { name: 'Change the Multi mute model' }))
    await pickInGate('Claude Opus 4.6', 'Save and run')
    await waitFor(() => expect(suggestRoute).toHaveBeenCalledTimes(2))

    expect(await screen.findByText(/This finding is muted now, so it cannot start a new search/)).toBeInTheDocument()
    expect(screen.getByText(/Findings like/)).toBeInTheDocument()
    expect(onGraphChanged).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Undo' }))
    await waitFor(() => expect(unmuteRoute).toHaveBeenCalledOnce())
    expect(sentTo(unmuteRoute)).toEqual({ projectId: 'p1', keys: ['v-seed'], undoBatch: BATCH })
  })

  test('a seed muted elsewhere still reloads the page', async () => {
    await openResults()
    suggestRoute.mockImplementationOnce(() => jsonResponse(409, { error: 'x', code: 'seed_changed' }))
    fireEvent.click(screen.getByRole('button', { name: 'Change the Multi mute model' }))
    await pickInGate('Claude Opus 4.6', 'Save and run')
    expect(await screen.findByText(/This finding changed or was muted/)).toBeInTheDocument()
    expect(onGraphChanged).toHaveBeenCalledOnce()
  })
})

describe('closing while the model gate saves', () => {
  test('starts no search once the modal is gone (review: the orphan search)', async () => {
    serve({})
    const answer = stub.fetch.getMockImplementation() as (url: string, init?: RequestInit) => Promise<Response>
    let release!: () => void
    const held = new Promise<void>(r => { release = r })
    stub.fetch.mockImplementation(async (url: string, init?: RequestInit) => {
      if (init?.method === 'PUT') await held
      return answer(url, init)
    })
    open()
    await pickInGate('Claude Opus 4.6', 'Save and run')
    await waitFor(() => expect(stub.calls(`/api/users/${GATE_USER}/settings`, 'PUT')).toHaveLength(1))

    fireEvent.keyDown(screen.getByRole('dialog'), { key: 'Escape' })
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    await act(async () => { release() })
    await waitFor(() => expect(stub.saved.multi_mute).toBe('claude-opus-4-6'))
    await act(async () => { await new Promise(r => setTimeout(r, 0)) })

    expect(suggestRoute).not.toHaveBeenCalled()
  })
})

describe('closing', () => {
  test('one refresh, the drawer told, and one toast that opens this batch', async () => {
    applyRoute.mockImplementationOnce(mutedWith({ workItemsAffected: 3, triageRunLive: false }))
    await openResults()
    fireEvent.click(muteAllButton())
    await screen.findByText('Muted 3')
    fireEvent.click(screen.getByRole('button', { name: 'Close' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(onGraphChanged).toHaveBeenCalledOnce()
    expect(onSeedMuted).toHaveBeenCalledOnce()
    expect(onMuted).toHaveBeenCalledWith(['v-seed', 'v-1', 'v-3'])
    expect(mockAddToast).toHaveBeenCalledOnce()
    const toast = mockAddToast.mock.calls[0][0]
    expect(toast.message).toBe('Muted 3 findings. 3 CypherFix items will update at the next triage run.')
    expect(toast.action.label).toBe('View muted')
    toast.action.onClick()
    expect(onViewMuted).toHaveBeenCalledWith({ token: BATCH })
  })

  test('while a triage run is live, the work items update after it', async () => {
    applyRoute.mockImplementationOnce(mutedWith({ workItemsAffected: 1, triageRunLive: true }))
    await openResults()
    fireEvent.click(within(rowOf('finding v-1')).getByRole('button', { name: 'Mute' }))
    await screen.findByText('Muted 1')
    fireEvent.click(screen.getByRole('button', { name: 'Close' }))
    await waitFor(() => expect(mockAddToast).toHaveBeenCalledOnce())
    expect(mockAddToast.mock.calls[0][0].message)
      .toBe('Muted 1 finding. 1 CypherFix item will update after the run in progress.')
    expect(onSeedMuted).not.toHaveBeenCalled()
  })

  test('nothing muted: no refresh and no toast', async () => {
    await openResults()
    fireEvent.click(screen.getByRole('button', { name: 'Close' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(onGraphChanged).not.toHaveBeenCalled()
    expect(mockAddToast).not.toHaveBeenCalled()
  })
})

describe('search errors', () => {
  test.each([
    ['providers_unreachable', 503, "Couldn't load your LLM providers, try again"],
    ['agent_unreachable', 503, "The agent service isn't running"],
    ['agent_timeout', 504, 'The model took too long, try again'],
    ['agent_outdated', 502, 'The agent is older than the webapp: rebuild it'],
    ['activation_busy', 409, 'A version is being activated; try again when it finishes.'],
    ['busy', 429, 'Too many Multi mute searches right now; try again in a moment.'],
  ])('%s shows its message and a Retry, never the gate', async (code, status, message) => {
    suggestRoute.mockImplementationOnce(() => jsonResponse(status, { error: 'server text', code, featureId: 'multi_mute' }))
    open()
    expect(await screen.findByText(message)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Save and run' })).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByText(/Findings like/)).toBeInTheDocument()
  })

  test('seed_changed reloads the page and offers no Retry', async () => {
    suggestRoute.mockImplementationOnce(() => jsonResponse(409, { error: 'x', code: 'seed_changed' }))
    open()
    expect(await screen.findByText(/This finding changed or was muted/)).toBeInTheDocument()
    expect(onGraphChanged).toHaveBeenCalledOnce()
    expect(screen.queryByRole('button', { name: 'Retry' })).toBeNull()
  })

  test('seed_not_muteable shows the server\'s reason', async () => {
    suggestRoute.mockImplementationOnce(() => jsonResponse(400, {
      error: 'a JS file container is not a finding', code: 'seed_not_muteable',
    }))
    open()
    expect(await screen.findByText('a JS file container is not a finding')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Retry' })).toBeNull()
  })

  test('superseded by a newer search from elsewhere: says so, with Retry', async () => {
    suggestRoute.mockImplementationOnce(() => jsonResponse(409, { error: 'x', code: 'superseded' }))
    open()
    expect(await screen.findByText('A newer Multi mute search replaced this one.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument()
  })

  test('a graph id seed is resolved server-side', async () => {
    open({ name: 'WCP', nodeId: '', label: 'Vulnerability', graphId: '812' } as never)
    await screen.findByText(/Findings like/)
    expect(sentTo(suggestRoute)).toEqual({ projectId: 'p1', graphId: '812' })
  })
})
