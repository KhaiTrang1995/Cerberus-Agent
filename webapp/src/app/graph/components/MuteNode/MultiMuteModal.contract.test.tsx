/**
 * Contract, consumer side: the modal renders the payload the agent really
 * produces.
 *
 * `multiMuteSuggest.contract.json` is written by the agent's
 * `agentic/tests/test_multi_mute_contract.py` from a real `suggest` run, and
 * that test fails when the producer drifts from it. This one fails when the
 * modal no longer reads it: a renamed key shows up here as a group, a member,
 * a verdict or a pre-check the modal stopped drawing.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, within } from '@testing-library/react'
import { jsonResponse, stubGateFetch, GATE_USER } from '@/components/shared/featureModelGate.testUtils'
import fixture from './multiMuteSuggest.contract.json'

vi.mock('@/components/ui', () => ({
  useAlertModal: () => ({ alertError: vi.fn(), dangerConfirm: vi.fn() }),
  useToast: () => ({ success: vi.fn(), error: vi.fn(), warning: vi.fn(), info: vi.fn(), addToast: vi.fn() }),
}))
vi.mock('@/providers/ProjectProvider', () => ({
  useProject: () => ({ userId: GATE_USER }),
  useOptionalProject: () => ({ userId: GATE_USER }),
}))

import { MultiMuteButton, MuteNodeProvider } from './index'

interface Member { key: string; name: string; verdict: string | null; checked: boolean }
interface Group {
  labels: string[]; ai: boolean; title: string | null; members: Member[]; probably_not: Member[]
}

/** The card's name as the contract defines it: an AI group by its title, else its labels. */
const cardName = (g: Group) => (g.ai && g.title ? g.title : g.labels.join(' · '))
const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')

beforeEach(() => {
  stubGateFetch({ multi_mute: 'provider/model-x' }, url =>
    url === '/api/triage/multi-mute/suggest'
      ? jsonResponse(200, fixture)
      : jsonResponse(404, { error: `unexpected ${url}` }))
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

async function openOnFixture() {
  render(
    <MuteNodeProvider projectId="p1" readOnly={false} onViewMuted={vi.fn()} onGraphChanged={vi.fn()}
      onOpenMuteRules={vi.fn()}>
      <MultiMuteButton seed={{ name: fixture.seed.name, nodeId: fixture.seed.key, label: fixture.seed.label }} />
    </MuteNodeProvider>,
  )
  fireEvent.click(screen.getByRole('button', { name: 'Multi mute' }))
  await screen.findByText(/Findings like/)
}

describe('the modal renders the agent\'s real suggest payload', () => {
  test('the seed, the AI read and the pool line', async () => {
    await openOnFixture()
    expect(screen.getByText(`Findings like “${fixture.seed.name}”`)).toBeInTheDocument()
    expect(screen.getByText(new RegExp(`AI read: .*${fixture.read.why}`))).toBeInTheDocument()
    expect(screen.getByText(new RegExp(`Compared with ${fixture.pool.total}`))).toBeInTheDocument()
  })

  test('every group, every member, and the pre-check the agent decided', async () => {
    await openOnFixture()
    const groups = fixture.groups as Group[]
    const checkedByKey = new Map<string, boolean>()
    for (const g of groups) for (const m of g.members) {
      checkedByKey.set(m.key, (checkedByKey.get(m.key) ?? false) || m.checked)
    }
    for (const g of groups) {
      const card = screen.getByRole('region', { name: new RegExp(`^${escape(cardName(g))}$`) })
      const toggle = within(card).getAllByRole('button').find(b => b.hasAttribute('aria-expanded'))!
      if (toggle.getAttribute('aria-expanded') === 'false') fireEvent.click(toggle)
      const drawn = (within(card).getAllByRole('checkbox') as HTMLInputElement[])
        .filter(b => b.getAttribute('aria-label')?.startsWith('Select '))
        .map(b => [b.getAttribute('aria-label'), b.checked])
      expect(drawn, `${cardName(g)} members and pre-checks`).toEqual(
        g.members.map(m => [`Select ${m.name}`, checkedByKey.get(m.key)]))
      if (g.probably_not.length) {
        expect(within(card).getByText(`Probably not (${g.probably_not.length})`)).toBeInTheDocument()
      }
    }
  })

  test('every verdict the agent sent is drawn', async () => {
    await openOnFixture()
    const verdicts = new Set((fixture.groups as Group[]).flatMap(g => g.members.map(m => m.verdict)))
    for (const v of verdicts) {
      if (v) expect(screen.getAllByText(v).length, `verdict ${v}`).toBeGreaterThan(0)
    }
  })
})
