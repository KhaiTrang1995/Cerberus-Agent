/**
 * Render tests for the AI Attack Surface page. The provider + hook are mocked
 * so we assert the rendering logic (card grid, chips, greying, findings table).
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'

// vitest config has no globals:true, so RTL's auto-cleanup never registers —
// unmount between tests so renders don't accumulate in the DOM.
afterEach(cleanup)

vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ projectId: 'p1' }) }))

const hookState = {
  targets: [] as unknown[],
  findings: [] as unknown[],
  run: null as unknown,
  logs: [] as unknown[],
  phase: { name: null, num: null },
  launching: false,
  loadingTargets: false,
  error: null,
  loadTargets: vi.fn(),
  loadFindings: vi.fn(),
  launch: vi.fn(),
  stop: vi.fn(),
}
vi.mock('@/hooks/useAiAttackSurface', () => ({ useAiAttackSurface: () => hookState }))

// Mock useAlertModal. The real hook throws unless <AlertProvider> is in the
// tree (it is mounted in app/layout.tsx in production, which these render tests
// bypass). vi.hoisted runs before the vi.mock factory so the refs are stable.
const alertSpies = vi.hoisted(() => ({
  alert: vi.fn(async () => {}),
  alertError: vi.fn(async () => {}),
  alertWarning: vi.fn(async () => {}),
  confirm: vi.fn(async () => true),
  dangerConfirm: vi.fn(async () => true),
}))
// Mock the DEEP path: useScanStartFailure (used by this page) imports the hook
// from '@/components/ui/AlertModal/AlertModal', not from the '@/components/ui'
// barrel, so mocking only the barrel leaves the real hook in the tree.
vi.mock('@/components/ui/AlertModal/AlertModal', async (orig) => {
  const real = (await orig()) as Record<string, unknown>
  return { ...real, useAlertModal: () => alertSpies }
})
vi.mock('@/components/ui', async (orig) => {
  const real = (await orig()) as Record<string, unknown>
  return { ...real, useAlertModal: () => alertSpies }
})

const AiAttackSurfacePage = (await import('./page')).default

beforeEach(() => {
  hookState.targets = []
  hookState.findings = []
  hookState.run = null
  hookState.logs = []
})

describe('AI Attack Surface page', () => {
  test('renders the title and the four tool cards', () => {
    render(<AiAttackSurfacePage />)
    expect(screen.getByText('AI Gauntlet')).toBeTruthy()
    expect(screen.getByText('garak')).toBeTruthy()
    expect(screen.getByText('PyRIT')).toBeTruthy()
    expect(screen.getByText('giskard')).toBeTruthy()
    expect(screen.getByText('promptfoo')).toBeTruthy()
  })

  test('renders the shared chip vocabulary in the filter bar', () => {
    render(<AiAttackSurfacePage />)
    expect(screen.getAllByText('Prompt Injection').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Jailbreak').length).toBeGreaterThan(0)
    // Hallucination appears in the filter bar AND the giskard card chips.
    expect(screen.getAllByText('Hallucination').length).toBeGreaterThan(0)
  })

  test('shows discovered count from targets', () => {
    hookState.targets = [{ baseUrl: 'http://h', path: '/c' }]
    render(<AiAttackSurfacePage />)
    expect(screen.getByText(/1 LLM endpoint\(s\) discovered/)).toBeTruthy()
  })

  test('renders findings table rows with ASR percentage', () => {
    hookState.findings = [{
      id: 'aiatk_1', source: 'garak', owaspLlmId: 'LLM01', payloadClass: 'garak-dan',
      target: 'http://h', endpointPath: '/v1/chat/completions', asr: 1.0, trials: 1,
      severity: 'high', evidence: 'dan.Dan_11_0/dan.DAN hits=1/1',
    }]
    render(<AiAttackSurfacePage />)
    expect(screen.getByText('Findings (1)')).toBeTruthy()
    expect(screen.getByText('garak-dan')).toBeTruthy()
    expect(screen.getByText('100%')).toBeTruthy()
    expect(screen.getByText('LLM01')).toBeTruthy()
  })

  test('the findings table leads with the Node ID column', () => {
    hookState.findings = [
      { id: 'aiatk_1', nodeId: '4711', source: 'garak', owaspLlmId: 'LLM01', severity: 'high' },
      { id: 'aiatk_2', source: 'pyrit', owaspLlmId: 'LLM02', severity: 'low' },
    ]
    render(<AiAttackSurfacePage />)
    const table = screen.getByText('Findings (2)').parentElement!.querySelector('table')!
    expect(table.querySelector('thead th')!.textContent).toBe('Node ID')
    expect(screen.getByRole('button', { name: 'Copy node ID 4711' })).toBeTruthy()
    // A row from a server older than the column shows the placeholder.
    const rows = table.querySelectorAll('tbody tr')
    const other = [...rows].find(r => r.textContent?.includes('pyrit'))!
    expect(other.querySelector('td')!.textContent).toBe('-')
  })

  test('running scan: spinner on its card, and Launch stays disabled (cannot relaunch)', () => {
    hookState.run = { run_id: 'r1', tool: 'garak', status: 'running' }
    hookState.targets = [{ baseUrl: 'http://h', path: '/c', method: 'POST', interfaceType: 'llm-chat' }]
    render(<AiAttackSurfacePage />)
    // the running tool's card shows the "Running…" state (with spinner)
    expect(screen.getByText('Running…')).toBeTruthy()
    // open garak, select a target + confirm RoE — Launch must STILL be disabled
    // purely because a scan is running (proves the can't-launch-while-running gate)
    fireEvent.click(screen.getByText('Running…'))
    fireEvent.click(screen.getByText('http://h/c'))
    fireEvent.click(screen.getByText(/I confirm this is an authorized/))
    const launchBtn = screen.getByText('Launch garak').closest('button') as HTMLButtonElement
    expect(launchBtn.disabled).toBe(true)
  })

  test('garak Configure stays enabled with no endpoint (custom targets allowed)', () => {
    render(<AiAttackSurfacePage />)   // targets = [] by default
    const btn = screen.getAllByText('Configure & launch')[0] as HTMLButtonElement
    expect(btn.disabled).toBe(false)
  })

  test('opening garak with no endpoints still shows the custom-target form + auth', () => {
    render(<AiAttackSurfacePage />)
    fireEvent.click(screen.getAllByText('Configure & launch')[0])
    expect(screen.getByText(/Attack a URL not in the graph/)).toBeTruthy()
    expect(screen.getByText('Target authentication')).toBeTruthy()
    expect(screen.getByText('Bearer token')).toBeTruthy()
  })

  test('opening garak (with a target) shows the four-block detail + the target row', () => {
    hookState.targets = [{ baseUrl: 'http://h:8000', path: '/v1/chat/completions', method: 'POST', interfaceType: 'llm-chat', modelFamily: 'qwen' }]
    render(<AiAttackSurfacePage />)
    fireEvent.click(screen.getAllByText('Configure & launch')[0])   // garak is first
    expect(screen.getByText('1. Targets')).toBeTruthy()
    expect(screen.getByText('2. Probes')).toBeTruthy()
    expect(screen.getByText('3. Run bounds')).toBeTruthy()
    expect(screen.getByText('http://h:8000/v1/chat/completions')).toBeTruthy()
  })

  test('opening PyRIT shows the multi-turn strategy block + Max turns', () => {
    render(<AiAttackSurfacePage />)
    // garak / pyrit / giskard each have a Configure button; pyrit is the second.
    fireEvent.click(screen.getAllByText('Configure & launch')[1])
    expect(screen.getByText('PyRIT - configure run')).toBeTruthy()
    expect(screen.getByText('2. Attack strategies')).toBeTruthy()
    expect(screen.getByText(/Crescendo/)).toBeTruthy()
    expect(screen.getByText('Max turns')).toBeTruthy()
    expect(screen.getByText('Launch PyRIT')).toBeTruthy()
  })

  test('opening giskard shows the scan detail (Probes block, Launch giskard)', () => {
    render(<AiAttackSurfacePage />)
    fireEvent.click(screen.getAllByText('Configure & launch')[2])   // giskard is third
    expect(screen.getByText('giskard - configure run')).toBeTruthy()
    expect(screen.getByText('2. Probes')).toBeTruthy()      // scan style -> "Probes"
    expect(screen.getByText(/Information Disclosure/)).toBeTruthy()
    expect(screen.getByText('Launch giskard')).toBeTruthy()
  })
})

describe('AI Attack Surface — garak probe selection grid', () => {
  beforeEach(() => { (hookState.launch as ReturnType<typeof vi.fn>).mockClear() })

  const openGarak = () => {
    render(<AiAttackSurfacePage />)
    fireEvent.click(screen.getAllByText('Configure & launch')[0])   // garak is first
  }

  test('shows the catalog: toolbar count (runnable families), a non-default family, a description', () => {
    openGarak()
    // 28 runnable = 33 catalog families minus the 5 black-box-incompatible ones.
    expect(screen.getByText(/4 \/ 28 selected/)).toBeTruthy()
    // a family that is NOT in the default MVP set is selectable...
    expect(screen.getByText('Malware Generation (malwaregen)')).toBeTruthy()
    // ...with its description rendered.
    expect(screen.getByText(/Requests evasion code/)).toBeTruthy()
  })

  test('Select all / Clear / Reset to defaults update the selection', () => {
    openGarak()
    // "Select all" picks the runnable probes — the 5 black-box-incompatible ones
    // (audio/visual_jailbreak/glitch/fileformats/agent_breaker) are excluded.
    fireEvent.click(screen.getByText('Select all'))
    expect(screen.getByText(/28 \/ 28 selected/)).toBeTruthy()
    fireEvent.click(screen.getByText('Clear'))
    expect(screen.getByText(/0 \/ 28 selected/)).toBeTruthy()
    fireEvent.click(screen.getByText('Reset to defaults'))
    expect(screen.getByText(/4 \/ 28 selected/)).toBeTruthy()
  })

  test('launch sends exactly the four default families (and the selected target)', () => {
    hookState.targets = [{ baseUrl: 'http://h:8000', path: '/v1/chat/completions', method: 'POST', interfaceType: 'llm-chat' }]
    openGarak()
    fireEvent.click(screen.getByText('http://h:8000/v1/chat/completions'))   // select target
    fireEvent.click(screen.getByText(/I confirm this is an authorized/))      // RoE
    fireEvent.click(screen.getByText('Launch garak'))

    expect(hookState.launch).toHaveBeenCalledTimes(1)
    const arg = (hookState.launch as ReturnType<typeof vi.fn>).mock.calls[0][0]
    expect(arg.tool).toBe('garak')
    expect([...arg.probes].sort()).toEqual(['dan', 'encoding', 'leakreplay', 'promptinject'])
    expect(arg.roe_confirmed).toBe(true)
    expect(arg.targets).toHaveLength(1)
    expect(arg.targets[0]).toMatchObject({ baseurl: 'http://h:8000', path: '/v1/chat/completions' })
    // run bounds: parallelism default 2; timeout default 600 min sent as seconds.
    expect(arg.bounds.parallelism).toBe(2)
    expect(arg.bounds.timeout).toBe(36000)   // 600 min * 60
  })

  test('Select all then launch sends the 28 runnable families (excludes incompatible + inactive)', () => {
    hookState.targets = [{ baseUrl: 'http://h:8000', path: '/v1/chat/completions', method: 'POST', interfaceType: 'llm-chat' }]
    openGarak()
    fireEvent.click(screen.getByText('Select all'))
    fireEvent.click(screen.getByText('http://h:8000/v1/chat/completions'))
    fireEvent.click(screen.getByText(/I confirm this is an authorized/))
    fireEvent.click(screen.getByText('Launch garak'))

    const arg = (hookState.launch as ReturnType<typeof vi.fn>).mock.calls[0][0]
    expect(arg.probes).toHaveLength(28)
    // black-box-incompatible probes must never be sent...
    for (const blocked of ['audio', 'visual_jailbreak', 'glitch', 'fileformats', 'agent_breaker']) {
      expect(arg.probes).not.toContain(blocked)
    }
    // ...nor the inactive-by-default families that would abort the run.
    for (const dead of ['doctor', 'donotanswer', 'fitd', 'goat', 'propile', 'smuggling', 'av_spam_scanning']) {
      expect(arg.probes).not.toContain(dead)
    }
  })

  test('clearing all probes disables Launch (cannot launch with zero probes)', () => {
    hookState.targets = [{ baseUrl: 'http://h:8000', path: '/v1/chat/completions', method: 'POST', interfaceType: 'llm-chat' }]
    openGarak()
    fireEvent.click(screen.getByText('http://h:8000/v1/chat/completions'))
    fireEvent.click(screen.getByText(/I confirm this is an authorized/))
    fireEvent.click(screen.getByText('Clear'))
    const launchBtn = (screen.getByText('Launch garak').closest('button')) as HTMLButtonElement
    expect(launchBtn.disabled).toBe(true)
  })
})
