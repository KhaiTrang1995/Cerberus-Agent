/**
 * The CypherFix section's two model pickers are ACCOUNT-wide: they read and
 * write the user's Triage review and CodeFix models (featureModels), saved at
 * once, and never the project's cypherfixLlmModel.
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor, within } from '@testing-library/react'
import { ToastProvider } from '@/components/ui/Toast/Toast'
import { GATE_USER, jsonResponse, stubGateFetch } from '@/components/shared/featureModelGate.testUtils'

vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: GATE_USER }) }))

import { FeatureModelGateProvider } from '@/components/shared/FeatureModelGate'
import { CypherFixSettingsSection } from './CypherFixSettingsSection'

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

const DATA = {
  cypherfixGithubToken: '',
  cypherfixDefaultRepo: '',
  cypherfixDefaultBranch: 'main',
  cypherfixBranchPrefix: 'cypherfix/',
  cypherfixRequireApproval: true,
  cypherfixLlmModel: 'legacy-project-model',
  triageReviewBudget: 150,
}

function renderSection(updateField = vi.fn()) {
  render(
    <ToastProvider>
      <FeatureModelGateProvider>
        <CypherFixSettingsSection data={DATA as never} updateField={updateField} />
      </FeatureModelGateProvider>
    </ToastProvider>,
  )
  return updateField
}

function field(featureId: string) {
  return document.querySelector(`[data-feature-model-field="${featureId}"]`) as HTMLElement
}

describe('CypherFix account models', () => {
  test('two pickers show the saved Triage review and CodeFix models, labelled as account-wide', async () => {
    stubGateFetch({ triage: 'claude-haiku-4-5' }, () => jsonResponse(404, {}))
    renderSection()
    await waitFor(() => expect(within(field('triage')).getByText('Claude Haiku 4.5')).toBeInTheDocument())
    expect(within(field('codefix')).getByText('Choose a model')).toBeInTheDocument()
    for (const id of ['triage', 'codefix']) {
      expect(within(field(id)).getByText(/Applies to all your projects · also in Global Settings → LLM Providers/)).toBeInTheDocument()
    }
    // The project's own model is no longer shown or edited here.
    expect(screen.queryByText('legacy-project-model')).toBeNull()
  })

  test('a pick saves that feature for the account, not the project', async () => {
    const stub = stubGateFetch({}, () => jsonResponse(404, {}))
    const updateField = renderSection()
    const codefix = field('codefix')
    await waitFor(() => expect(within(codefix).getByText('Choose a model')).toBeInTheDocument())
    fireEvent.click(within(codefix).getByText('Choose a model'))
    fireEvent.click(within(codefix).getByText('Claude Opus 4.6'))
    await waitFor(() => expect(stub.saved).toEqual({ codefix: 'claude-opus-4-6' }))
    const puts = stub.calls(`/api/users/${GATE_USER}/settings`, 'PUT')
    expect(puts).toHaveLength(1)
    expect(JSON.parse(puts[0][1]!.body as string)).toEqual({ featureModels: { codefix: 'claude-opus-4-6' } })
    expect(updateField).not.toHaveBeenCalledWith('cypherfixLlmModel', expect.anything())
  })

  test('clearing sends an empty model for that feature', async () => {
    const stub = stubGateFetch({ triage: 'claude-haiku-4-5' }, () => jsonResponse(404, {}))
    renderSection()
    fireEvent.click(await screen.findByRole('button', { name: 'Clear the Triage review model' }))
    await waitFor(() => expect(stub.saved).toEqual({}))
    expect(JSON.parse(stub.calls(`/api/users/${GATE_USER}/settings`, 'PUT')[0][1]!.body as string))
      .toEqual({ featureModels: { triage: '' } })
  })
})
