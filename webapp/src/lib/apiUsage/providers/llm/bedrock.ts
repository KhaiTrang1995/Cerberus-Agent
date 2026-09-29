/**
 * AWS Bedrock (catalogue C11), checked in the auth mode the agent itself picks:
 * the Bedrock API key (bearer) when one is saved, else the IAM key pair.
 *   - API key: `GET bedrock.{region}.amazonaws.com/foundation-models`, a free
 *     control-plane call, with the key as a Bearer token.
 *   - IAM: STS GetCallerIdentity at the region's STS endpoint proves the pair;
 *     it says nothing about Bedrock permissions, and the row says so.
 * The region is part of a hostname in both modes, so it is validated before
 * any request is built: a saved value that is not a region name is never called.
 */
import { str } from '../../parse'
import { body, errorResult, messageOf, notCheckedResult, shapeError, statusError, validResult } from '../../results'
import type { ProbeDef, ProbeRequest, ProbeResponse, ProbeResult } from '../../types'
import { hideEmails, INVALID_REGION_MESSAGE, isValidAwsRegion, stsGetCallerIdentity } from '../sources/awsSts'

export const IAM_NOTE = 'Bedrock permission not verified: the check proves the IAM credentials only'

export function apiKeyRequest(token: string, region: string): ProbeRequest {
  if (!isValidAwsRegion(region)) throw new Error(INVALID_REGION_MESSAGE)
  return {
    method: 'GET',
    url: `https://bedrock.${region}.amazonaws.com/foundation-models`,
    headers: { Authorization: `Bearer ${token}` },
  }
}

/** `x-amzn-ErrorType: AccessDeniedException:http://internal.amazon.com/coral/…` -> AccessDeniedException */
export function bedrockErrorCode(res: ProbeResponse): string | undefined {
  return str(res.headers['x-amzn-errortype']?.split(':')[0])
}

export function parseApiKey(res: ProbeResponse, region: string): ProbeResult {
  if (res.status === 200) {
    // The model list can outgrow the read cap; the 200 alone proves the key.
    const listed = Array.isArray(body(res).modelSummaries) || (res.truncated && res.text.includes('"modelSummaries"'))
    if (!listed) return shapeError(res)
    return validResult({ notes: [`Bedrock API key accepted in ${region}`] })
  }

  const code = bedrockErrorCode(res)
  // A denial names the IAM principal, whose session name can be an email.
  const message = hideEmails(messageOf(res))
  const opts = { httpStatus: res.status, providerCode: code }
  if (code === 'AccessDeniedException') {
    return errorResult('forbidden', message || 'the key is valid but may not list Bedrock foundation models', opts)
  }
  if (code === 'ThrottlingException' || res.status === 429) {
    return errorResult('rate_limited', message || 'throttled while checking; try again later', opts)
  }
  if (code === 'ExpiredTokenException') return errorResult('invalid_key', message || 'the Bedrock API key has expired', opts)
  // "Authorization header is missing", "Invalid API Key format…", UnrecognizedClientException.
  if (res.status === 401 || res.status === 403) {
    return errorResult('invalid_key', message || 'AWS rejected the Bedrock API key', opts)
  }
  return statusError(res)
}

export const bedrockProbe: ProbeDef = {
  id: 'llm-bedrock',
  service: 'bedrock',
  label: 'AWS Bedrock',
  group: 'llm',
  field: 'apiKey',
  kind: 'validity',
  costNote: 'Free: listing foundation models (API key) or GetCallerIdentity (IAM) is not billed',
  docsUrl: 'https://docs.aws.amazon.com/bedrock/latest/userguide/api-keys-use.html',
  dashboardUrl: 'https://console.aws.amazon.com/bedrock/home',
  verifiedOn: null,
  endpoint: 'GET bedrock.<region>.amazonaws.com/foundation-models (API key) · POST sts.<region>.amazonaws.com/ (IAM)',
  // ctx.key is the row's apiKey, which Bedrock does not use: its credentials are companions.
  run: async ctx => {
    const c = ctx.companions
    const region = c.awsRegion ?? ''
    if (!isValidAwsRegion(region)) return errorResult('unexpected_response', INVALID_REGION_MESSAGE)

    const bearer = c.awsBearerToken ?? ''
    if (bearer) return parseApiKey(await ctx.http(apiKeyRequest(bearer, region)), region)

    const accessKeyId = c.awsAccessKeyId ?? ''
    const secretKey = c.awsSecretKey ?? ''
    if (!accessKeyId || !secretKey) {
      return notCheckedResult('companion_missing', 'Bedrock needs an API key, or both the IAM access key ID and the secret access key')
    }
    const result = await stsGetCallerIdentity(ctx.http, { accessKeyId, secretKey }, region, ctx.now)
    if (result.outcome !== 'valid_no_usage') return result
    return { ...result, notes: [...(result.notes ?? []), IAM_NOTE] }
  },
}
