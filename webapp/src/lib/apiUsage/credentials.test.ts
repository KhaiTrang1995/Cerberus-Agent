import { describe, test, expect } from 'vitest'
import { buildJobs, splitExtraKeys, trackedFields, WHITESPACE_WARNING, type LlmProviderRow } from './credentials'
import { inventoryChanges, buildInventory, llmInventoryHint, type LlmInventoryRow } from './inventory'
import type { ProbeDef } from './types'

const probe = (over: Partial<ProbeDef>): ProbeDef => ({
  id: 'svc', service: 'svc', label: 'Service', group: 'keys', field: 'svcKey', kind: 'usage',
  costNote: '', docsUrl: '', dashboardUrl: '', verifiedOn: null, endpoint: 'GET x', run: async () => ({ outcome: 'valid_no_usage', meters: [] }),
  ...over,
})

const shodanLike = probe({ id: 'shodan', service: 'shodan', label: 'Shodan', field: 'shodanApiKey', rotationTool: 'shodan' })
const gheLike = probe({
  id: 'ghe', service: 'ghe', label: 'GitHub Enterprise', field: 'githubEnterpriseToken',
  companions: [{ field: 'githubEnterpriseHost', required: true }],
})
const hunterHowLike = probe({
  id: 'hunterhow', service: 'hunterhow', label: 'hunter.how', field: 'hunterHowApiKey', rotationTool: 'hunterhow',
  kind: 'none', notCheckedReason: 'costs_credits', notCheckedMessage: 'would spend a query', run: undefined,
})
const googleLike = probe({
  id: 'google-cse', service: 'google-cse', label: 'Google', field: 'googleApiKey', kind: 'none',
  companions: [{ field: 'googleApiCx', required: true }], notCheckedReason: 'costs_credits', run: undefined,
})
const awsLike = probe({
  id: 'aws', service: 'aws', label: 'AWS', field: 'awsId', reportLoneCompanion: true,
  companions: [{ field: 'awsSecret', required: true }, { field: 'awsSession', required: false }],
})

describe('splitExtraKeys', () => {
  test('splits like the settings GET: on \\n, blank lines dropped, lines kept as stored', () => {
    expect(splitExtraKeys('a\n\n  \nb \r\n c')).toEqual(['a', 'b \r', ' c'])
    expect(splitExtraKeys('')).toEqual([])
    expect(splitExtraKeys(null)).toEqual([])
  })
})

describe('buildJobs: settings keys', () => {
  test('an empty field is skipped, with its label, and never becomes a job', () => {
    const plan = buildJobs({ settings: { shodanApiKey: '' }, rotationRows: [], probes: [shodanLike] })
    expect(plan.jobs).toEqual([])
    expect(plan.skippedEmpty).toEqual([{ field: 'shodanApiKey', label: 'Shodan' }])
  })

  test('primary + rotation keys expand to one job each, primary first', () => {
    const plan = buildJobs({
      settings: { shodanApiKey: 'KEY-A-0001' },
      rotationRows: [{ toolName: 'shodan', extraKeys: 'KEY-B-0002\nKEY-C-0003' }],
      probes: [shodanLike],
    })
    expect(plan.jobs.map(j => [j.key, j.keyRole, j.keyIndex, j.keyHint])).toEqual([
      ['KEY-A-0001', 'primary', 0, '••••••••0001'],
      ['KEY-B-0002', 'rotation', 1, '••••••••0002'],
      ['KEY-C-0003', 'rotation', 2, '••••••••0003'],
    ])
    expect(plan.secrets).toEqual(expect.arrayContaining(['KEY-A-0001', 'KEY-B-0002', 'KEY-C-0003']))
  })

  test('rotation keys are checked even with an empty primary (the scans pool them anyway)', () => {
    const plan = buildJobs({ settings: {}, rotationRows: [{ toolName: 'shodan', extraKeys: 'ONLY-EXTRA' }], probes: [shodanLike] })
    expect(plan.jobs.map(j => [j.keyRole, j.keyIndex])).toEqual([['rotation', 1]])
    expect(plan.skippedEmpty).toEqual([])
  })

  test('a key pasted twice is checked once, and the kept row says where else it is listed', () => {
    const plan = buildJobs({
      settings: { shodanApiKey: 'DUP-KEY-1' },
      rotationRows: [{ toolName: 'shodan', extraKeys: 'OTHER-KEY\nDUP-KEY-1' }],
      probes: [shodanLike],
    })
    expect(plan.jobs.map(j => j.key)).toEqual(['DUP-KEY-1', 'OTHER-KEY'])
    expect(plan.jobs[0].notes).toEqual(['Also listed as rotation #2'])
  })

  test('keys are probed exactly as stored; surrounding whitespace becomes a warning', () => {
    const plan = buildJobs({
      settings: { shodanApiKey: ' PADDED-KEY ' },
      rotationRows: [{ toolName: 'shodan', extraKeys: 'CRLF-KEY\r\nCLEAN-KEY' }],
      probes: [shodanLike],
    })
    expect(plan.jobs.map(j => j.key)).toEqual([' PADDED-KEY ', 'CRLF-KEY\r', 'CLEAN-KEY'])
    expect(plan.jobs.map(j => j.warnings)).toEqual([[WHITESPACE_WARNING], [WHITESPACE_WARNING], []])
  })

  test('a token whose required companion is missing is not checked (no call)', () => {
    const plan = buildJobs({ settings: { githubEnterpriseToken: 'ghp_TOKEN0001' }, rotationRows: [], probes: [gheLike] })
    expect(plan.jobs).toHaveLength(1)
    expect(plan.jobs[0].immediate).toMatchObject({ outcome: 'not_checked', notCheckedReason: 'companion_missing' })
  })

  test('a companion alone (a GHE host without a token) is skipped, not reported', () => {
    const plan = buildJobs({ settings: { githubEnterpriseHost: 'ghe.example.test' }, rotationRows: [], probes: [gheLike] })
    expect(plan.jobs).toEqual([])
    expect(plan.skippedEmpty.map(s => s.field)).toEqual(['githubEnterpriseToken'])
    // A host is configuration, not a secret: nothing to scrub.
    expect(plan.secrets).toEqual([])
  })

  test('reportLoneCompanion: half of a pair is reported as companion_missing', () => {
    const plan = buildJobs({ settings: { awsSecret: 'SECRET-PART-9999' }, rotationRows: [], probes: [awsLike] })
    expect(plan.jobs).toHaveLength(1)
    expect(plan.jobs[0].immediate?.notCheckedReason).toBe('companion_missing')
    expect(plan.jobs[0].keyHint).toBe('••••••••9999')
  })

  test('a not-checked service is one row however many rotation keys it has', () => {
    const plan = buildJobs({
      settings: { hunterHowApiKey: 'HH-1' },
      rotationRows: [{ toolName: 'hunterhow', extraKeys: 'HH-2\nHH-3' }],
      probes: [hunterHowLike],
    })
    expect(plan.jobs).toHaveLength(1)
    expect(plan.jobs[0].immediate).toMatchObject({ notCheckedReason: 'costs_credits', notes: ['would spend a query'] })
    expect(plan.jobs[0].notes).toEqual(['Also covers 2 rotation keys'])
  })

  test('Google: no CX -> companion_missing; with CX -> costs_credits; never a call', () => {
    const noCx = buildJobs({ settings: { googleApiKey: 'AIza-KEY' }, rotationRows: [], probes: [googleLike] })
    expect(noCx.jobs[0].immediate?.notCheckedReason).toBe('companion_missing')
    const withCx = buildJobs({ settings: { googleApiKey: 'AIza-KEY', googleApiCx: 'cx:1' }, rotationRows: [], probes: [googleLike] })
    expect(withCx.jobs[0].immediate?.notCheckedReason).toBe('costs_credits')
  })

  test('jobs follow registry order, whatever the probe array order of rotation rows', () => {
    const plan = buildJobs({
      settings: { shodanApiKey: 'S', githubEnterpriseToken: 'G', githubEnterpriseHost: 'ghe.example.test' },
      rotationRows: [],
      probes: [gheLike, shodanLike],
    })
    expect(plan.jobs.map(j => j.probe.id)).toEqual(['ghe', 'shodan'])
    expect(plan.jobs[0].order).toBeLessThan(plan.jobs[1].order)
  })
})

describe('buildJobs: LLM providers', () => {
  const llmProbe = probe({ id: 'llm-openai', service: 'openai', label: 'OpenAI', group: 'llm', field: 'apiKey' })
  const compatProbe = probe({ id: 'llm-openai-compatible', service: 'oai-compat', label: 'OpenAI-compatible', group: 'llm', field: 'apiKey' })
  const row = (over: Partial<LlmProviderRow>): LlmProviderRow => ({
    id: 'p1', providerType: 'openai', name: 'My OpenAI', apiKey: 'sk-TEST-0000', baseUrl: '', awsRegion: 'us-east-1',
    awsAccessKeyId: '', awsSecretKey: '', awsBearerToken: '', ...over,
  })

  test('one job per provider row, identified by llm:<id>, after every settings key', () => {
    const plan = buildJobs({
      settings: { shodanApiKey: 'S' }, rotationRows: [], probes: [shodanLike],
      llmRows: [row({})], llmProbes: { openai: llmProbe },
    })
    expect(plan.jobs.map(j => [j.probe.id, j.field, j.sourceName])).toEqual([
      ['shodan', 'shodanApiKey', undefined],
      ['llm-openai', 'llm:p1', 'My OpenAI'],
    ])
    expect(plan.jobs[1].companions).toMatchObject({ baseUrl: '', awsRegion: 'us-east-1' })
  })

  test('a keyless row is skipped, except an OpenAI-compatible one (its probe explains)', () => {
    const plan = buildJobs({
      settings: {}, rotationRows: [], probes: [],
      llmRows: [row({ id: 'a', apiKey: '' }), row({ id: 'b', providerType: 'openai_compatible', apiKey: '', baseUrl: 'http://host.docker.internal:11434/v1' })],
      llmProbes: { openai: llmProbe, openai_compatible: compatProbe },
    })
    expect(plan.skippedEmpty).toEqual([{ field: 'llm:a', label: 'My OpenAI' }])
    expect(plan.jobs.map(j => j.field)).toEqual(['llm:b'])
  })

  test('an unknown provider type is listed as pending, never called', () => {
    const plan = buildJobs({ settings: {}, rotationRows: [], probes: [], llmRows: [row({ providerType: 'newthing' })], llmProbes: {} })
    expect(plan.jobs[0].immediate?.notCheckedReason).toBe('pending')
  })

  test('every LLM secret is in the scrub list', () => {
    const plan = buildJobs({
      settings: {}, rotationRows: [], probes: [],
      llmRows: [row({ providerType: 'bedrock', apiKey: '', awsAccessKeyId: 'AKIDTEST0001', awsSecretKey: 'SECRET-0002' })],
      llmProbes: { bedrock: llmProbe },
    })
    expect(plan.secrets).toEqual(expect.arrayContaining(['AKIDTEST0001', 'SECRET-0002']))
  })
})

describe('inventory', () => {
  test('the server (raw values) and the page (masked values) land on the same inventory', () => {
    const tracked = trackedFields([shodanLike, gheLike])
    const server = buildInventory(
      { shodanApiKey: 'RAWKEY-1234', githubEnterpriseToken: 'ghp_ABCDEFG9', githubEnterpriseHost: 'ghe.example.test' },
      { shodan: 2 }, tracked,
    )
    const page = buildInventory(
      { shodanApiKey: '••••••••1234', githubEnterpriseToken: '••••••••EFG9', githubEnterpriseHost: 'ghe.example.test' },
      { shodan: 2 }, tracked,
    )
    expect(inventoryChanges(server, page)).toEqual([])
    expect(server.shodanApiKey).toEqual({ hint: '••••••••1234', extraKeys: 2 })
  })

  test('a changed key, a new rotation key or a removed field is a change', () => {
    const tracked = trackedFields([shodanLike])
    const saved = buildInventory({ shodanApiKey: 'KEY-1234' }, { shodan: 1 }, tracked)
    expect(inventoryChanges(saved, buildInventory({ shodanApiKey: 'KEY-9999' }, { shodan: 1 }, tracked))).toEqual(['shodanApiKey'])
    expect(inventoryChanges(saved, buildInventory({ shodanApiKey: 'KEY-1234' }, { shodan: 2 }, tracked))).toEqual(['shodanApiKey'])
    expect(inventoryChanges(saved, buildInventory({}, {}, tracked))).toEqual(['shodanApiKey'])
  })

  // The page holds LLM rows as the LLM providers GET returns them (keys masked,
  // region and base URL plain), the server reads them raw. If the two hints ever
  // differ, every report opens with a false "your keys changed" banner.
  test('an LLM row hints the same raw (server) and masked (page): bedrock, openai_compatible', () => {
    const raw: LlmInventoryRow[] = [
      { id: 'b1', providerType: 'bedrock', apiKey: '', awsAccessKeyId: 'AKIDTEST0001', awsBearerToken: '', awsRegion: 'eu-west-1' },
      { id: 'b2', providerType: 'bedrock', apiKey: '', awsAccessKeyId: 'AKIDTEST0002', awsBearerToken: 'ABSK-TEST-7777', awsRegion: 'us-east-1' },
      { id: 'c1', providerType: 'openai_compatible', apiKey: 'sk-local-TEST-4242', baseUrl: 'http://host.docker.internal:11434/v1' },
      { id: 'c2', providerType: 'openai_compatible', apiKey: '', baseUrl: 'http://llm.example.test/v1' },
    ]
    const masked: LlmInventoryRow[] = [
      { id: 'b1', providerType: 'bedrock', apiKey: '', awsAccessKeyId: '••••••••0001', awsBearerToken: '', awsRegion: 'eu-west-1' },
      { id: 'b2', providerType: 'bedrock', apiKey: '', awsAccessKeyId: '••••••••0002', awsBearerToken: '••••••••7777', awsRegion: 'us-east-1' },
      { id: 'c1', providerType: 'openai_compatible', apiKey: '••••••••4242', baseUrl: 'http://host.docker.internal:11434/v1' },
      { id: 'c2', providerType: 'openai_compatible', apiKey: '', baseUrl: 'http://llm.example.test/v1' },
    ]
    raw.forEach((r, i) => expect(llmInventoryHint(r)).toBe(llmInventoryHint(masked[i])))
    expect(inventoryChanges(buildInventory({}, {}, [], raw), buildInventory({}, {}, [], masked))).toEqual([])
    expect(llmInventoryHint(raw[0])).toBe('••••••••0001|eu-west-1')
    expect(llmInventoryHint(raw[1])).toBe('••••••••7777|us-east-1')
    expect(llmInventoryHint(raw[2])).toBe('••••••••4242|http://host.docker.internal:11434/v1')

    // Not equal by accident: what decides the probe is part of the hint.
    expect(llmInventoryHint({ ...masked[0], awsRegion: 'us-west-2' })).not.toBe(llmInventoryHint(raw[0]))
    expect(llmInventoryHint({ ...masked[2], baseUrl: 'http://other.example.test/v1' })).not.toBe(llmInventoryHint(raw[2]))
  })

  test('buildJobs stores the inventory it ran on', () => {
    const plan = buildJobs({
      settings: { shodanApiKey: 'KEY-1234' }, rotationRows: [{ toolName: 'shodan', extraKeys: 'X\nY' }], probes: [shodanLike],
    })
    expect(plan.inventory).toEqual({ shodanApiKey: { hint: '••••••••1234', extraKeys: 2 } })
  })
})
