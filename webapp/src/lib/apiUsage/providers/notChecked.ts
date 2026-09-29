/**
 * Credentials the report lists but never calls a provider for, each with the
 * reason the row shows. A check that would spend the user's quota or money, or
 * start a tunnel, or reach a host the settings do not know, is never made.
 */
import type { ProbeDef } from '../types'

const NONE = { kind: 'none' as const, verifiedOn: null, endpoint: '—' }

export const hunterHowProbe: ProbeDef = {
  ...NONE,
  id: 'hunterhow',
  service: 'hunterhow',
  label: 'hunter.how',
  group: 'uncover',
  field: 'hunterHowApiKey',
  rotationTool: 'hunterhow',
  notCheckedReason: 'costs_credits',
  notCheckedMessage: 'hunter.how has no free usage API: its account page needs a web login, and any API check spends a query and 10 results',
  costNote: 'Not checked: every hunter.how API call spends quota',
  docsUrl: 'https://hunter.how/search-api',
  dashboardUrl: 'https://hunter.how/profile',
}

export const googleCseProbe: ProbeDef = {
  ...NONE,
  id: 'google-cse',
  service: 'google-cse',
  label: 'Google Custom Search',
  group: 'uncover',
  field: 'googleApiKey',
  companions: [{ field: 'googleApiCx', required: true }],
  notCheckedReason: 'costs_credits',
  notCheckedMessage: 'Checking would spend 1 of your 100 daily queries. Google closes the Custom Search JSON API to existing customers on 1 January 2027',
  costNote: 'Not checked: the only check is a billable search',
  docsUrl: 'https://developers.google.com/custom-search/v1/overview',
  dashboardUrl: 'https://console.cloud.google.com/apis/api/customsearch.googleapis.com/quotas',
}

export const ngrokProbe: ProbeDef = {
  ...NONE,
  id: 'ngrok',
  service: 'ngrok',
  label: 'ngrok',
  group: 'keys',
  field: 'ngrokAuthtoken',
  notCheckedReason: 'no_api',
  notCheckedMessage: 'An ngrok authtoken has no account API; checking it would mean starting a tunnel',
  costNote: 'Not checked',
  docsUrl: 'https://ngrok.com/docs/agent/#authtokens',
  dashboardUrl: 'https://dashboard.ngrok.com/get-started/your-authtoken',
}

export const chiselProbe: ProbeDef = {
  ...NONE,
  id: 'chisel',
  service: 'chisel',
  label: 'Chisel',
  group: 'keys',
  field: 'chiselServerUrl',
  companions: [{ field: 'chiselAuth', required: false }],
  notCheckedReason: 'no_api',
  notCheckedMessage: 'Chisel points to your own server; there is no provider account to check',
  costNote: 'Not checked',
  docsUrl: 'https://github.com/jpillora/chisel',
  dashboardUrl: 'https://github.com/jpillora/chisel',
}

export const dockerHubProbe: ProbeDef = {
  ...NONE,
  id: 'docker',
  service: 'docker',
  label: 'Docker Hub',
  group: 'sources',
  field: 'trufflehogDockerToken',
  notCheckedReason: 'needs_username',
  notCheckedMessage: 'Docker Hub needs the account username to verify a token; RedAmon stores only the token',
  costNote: 'Not checked',
  docsUrl: 'https://docs.docker.com/security/for-developers/access-tokens/',
  dashboardUrl: 'https://app.docker.com/settings/personal-access-tokens',
}

const HOST_PER_SCAN = 'Checked when a scan runs against the host you choose; Settings stores no host to call'

export const jenkinsProbe: ProbeDef = {
  ...NONE,
  id: 'jenkins',
  service: 'jenkins',
  label: 'Jenkins',
  group: 'sources',
  field: 'trufflehogJenkinsPassword',
  companions: [{ field: 'trufflehogJenkinsUsername', required: false }],
  notCheckedReason: 'host_per_scan',
  notCheckedMessage: HOST_PER_SCAN,
  costNote: 'Not checked',
  docsUrl: 'https://www.jenkins.io/doc/book/using/remote-access-api/',
  dashboardUrl: 'https://www.jenkins.io/doc/book/using/remote-access-api/',
}

export const elasticsearchProbe: ProbeDef = {
  ...NONE,
  id: 'elasticsearch',
  service: 'elasticsearch',
  label: 'Elasticsearch',
  group: 'sources',
  field: 'trufflehogElasticApiKey',
  companions: [
    { field: 'trufflehogElasticUsername', required: false },
    { field: 'trufflehogElasticPassword', required: false },
    { field: 'trufflehogElasticServiceToken', required: false },
  ],
  notCheckedReason: 'host_per_scan',
  notCheckedMessage: HOST_PER_SCAN,
  costNote: 'Not checked',
  docsUrl: 'https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-security-authenticate',
  dashboardUrl: 'https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-security-authenticate',
}

export const gitProbe: ProbeDef = {
  ...NONE,
  id: 'git',
  service: 'git',
  label: 'Git (HTTPS)',
  group: 'sources',
  field: 'trufflehogGitToken',
  companions: [{ field: 'trufflehogGitUsername', required: false }],
  notCheckedReason: 'host_per_scan',
  notCheckedMessage: HOST_PER_SCAN,
  costNote: 'Not checked',
  docsUrl: 'https://git-scm.com/docs/gitcredentials',
  dashboardUrl: 'https://git-scm.com/docs/gitcredentials',
}
