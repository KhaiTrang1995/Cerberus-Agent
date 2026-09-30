/**
 * Saving a Tradecraft resource offers the user's optional section-picker model.
 *
 * The picker is optional (unset means pages are picked by text match), so the
 * prompt must never block the save: Cancel saves too. Someone who declined is
 * not asked again on the next save, and a user with a saved picker model is
 * never asked at all.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'
import { GATE_USER, jsonResponse, stubGateFetch, type GateFetchStub } from '@/components/shared/featureModelGate.testUtils'

vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: GATE_USER }) }))

const RESOURCE_URL = `/api/users/${GATE_USER}/tradecraft-resources/r1`
const RESOURCE = { id: 'r1', name: 'HackTricks', url: 'https://book.hacktricks.wiki', enabled: true, llmModel: 'claude-haiku-4-5' }

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

// The "declined" memory is module state, so each test gets fresh modules; the
// provider and the form must come from the same load to share the context.
async function load() {
  vi.resetModules()
  const [{ FeatureModelGateProvider }, { TradecraftResourceForm }, { AlertProvider }] = await Promise.all([
    import('@/components/shared/FeatureModelGate'),
    import('./TradecraftResourceForm'),
    import('@/components/ui/AlertModal/AlertModal'),
  ])
  return function renderForm(onSave = vi.fn()) {
    render(
      <AlertProvider>
        <FeatureModelGateProvider>
          <TradecraftResourceForm userId={GATE_USER} resource={RESOURCE} onSave={onSave} onCancel={vi.fn()} />
        </FeatureModelGateProvider>
      </AlertProvider>,
    )
    return onSave
  }
}

function saveEdited() {
  fireEvent.click(screen.getByRole('checkbox', { name: /Enabled/ }))
  fireEvent.click(screen.getByRole('button', { name: 'Save changes' }))
}

function puts(stub: GateFetchStub) {
  return stub.calls(RESOURCE_URL, 'PUT')
}

let stub: GateFetchStub

describe('section picker prompt on save', () => {
  beforeEach(() => {
    stub = stubGateFetch({}, () => jsonResponse(200, RESOURCE))
  })

  test('Cancel still saves the resource, and the prompt explains that', async () => {
    const renderForm = await load()
    const onSave = renderForm()
    saveEdited()
    expect(await screen.findByText(/Cancel saves the resource either way/)).toBeInTheDocument()
    fireEvent.click(screen.getAllByRole('button', { name: 'Cancel' }).at(-1)!)
    await waitFor(() => expect(onSave).toHaveBeenCalledTimes(1))
    expect(puts(stub)).toHaveLength(1)
    expect(stub.saved).toEqual({})
  })

  test('once declined, the next save is not asked again', async () => {
    const renderForm = await load()
    const first = renderForm()
    saveEdited()
    await screen.findByText(/Cancel saves the resource either way/)
    fireEvent.click(screen.getAllByRole('button', { name: 'Cancel' }).at(-1)!)
    await waitFor(() => expect(first).toHaveBeenCalled())
    cleanup()

    const second = renderForm()
    saveEdited()
    await waitFor(() => expect(second).toHaveBeenCalled())
    expect(screen.queryByText(/Cancel saves the resource either way/)).toBeNull()
    expect(puts(stub)).toHaveLength(2)
  })

  test('a saved picker model means no prompt at all', async () => {
    stub = stubGateFetch({ tradecraft_section_picker: 'claude-haiku-4-5' }, () => jsonResponse(200, RESOURCE))
    const renderForm = await load()
    const onSave = renderForm()
    saveEdited()
    await waitFor(() => expect(onSave).toHaveBeenCalled())
    expect(screen.queryByText(/Cancel saves the resource either way/)).toBeNull()
  })
})
