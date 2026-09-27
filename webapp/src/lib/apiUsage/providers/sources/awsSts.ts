/**
 * AWS access key (catalogue B4): STS GetCallerIdentity, SigV4-signed. AWS
 * documents it as needing no permission ("works even when explicitly
 * denied") and does not bill it, so it proves the key pair whatever the key's
 * policies. The Bedrock probe (C11) reuses `stsGetCallerIdentity` for its IAM
 * mode, against the region's own STS endpoint.
 *
 * Only the access key id (in Authorization) and the session token leave the
 * server; the secret key is used to sign and is never sent.
 */
import { signAwsRequest } from '../../sign/sigv4'
import { isPlainObject, str } from '../../parse'
import { body, errorResult, kindForStatus, notCheckedResult, shapeError, statusError, validResult } from '../../results'
import type { ProbeDef, ProbeHttp, ProbeRequest, ProbeResponse, ProbeResult } from '../../types'

export interface AwsCredentials {
  accessKeyId: string
  secretKey: string
  sessionToken?: string
}

const STS_BODY = 'Action=GetCallerIdentity&Version=2011-06-15'

/**
 * Commercial, GovCloud and ISO region names. The region is interpolated into a
 * hostname, so nothing else may pass: a saved `us-east-1.evil.test#` would
 * otherwise send signed credentials (or a Bedrock bearer key) to another host.
 */
const AWS_REGION = /^[a-z]{2}(-gov|-iso[a-z]*)?-[a-z]+-\d{1,2}$/

export function isValidAwsRegion(region: string): boolean {
  return AWS_REGION.test(region)
}

export const INVALID_REGION_MESSAGE = 'invalid AWS region: the saved region is not an AWS region name, so nothing was called'

/**
 * An assumed-role ARN ends with the session name, which AWS SSO sets to the
 * user's email address. The report never holds an email, so it is hidden.
 */
export function hideEmails(text: string): string {
  return text.replace(/[^\s/:@]+@[^\s/:@]+\.[^\s/:@]+/g, '(email hidden)')
}

/**
 * `region` undefined = the global endpoint, which AWS signs as us-east-1 (B4).
 * A region = that region's endpoint, signed for it (Bedrock's IAM mode).
 */
export function stsRequest(creds: AwsCredentials, region: string | undefined, now: Date): ProbeRequest {
  if (region !== undefined && !isValidAwsRegion(region)) throw new Error(INVALID_REGION_MESSAGE)
  const host = region === undefined ? 'sts.amazonaws.com' : `sts.${region}.amazonaws.com`
  const signed = signAwsRequest({
    method: 'POST',
    host,
    path: '/',
    region: region ?? 'us-east-1',
    service: 'sts',
    body: STS_BODY,
    contentType: 'application/x-www-form-urlencoded',
    accessKeyId: creds.accessKeyId,
    secretKey: creds.secretKey,
    sessionToken: creds.sessionToken || undefined,
    now,
  })
  // STS answers in XML unless asked for JSON; the JSON form is what parse reads.
  return { method: 'POST', url: `https://${host}/`, headers: { ...signed, Accept: 'application/json' }, body: STS_BODY }
}

function xmlTag(text: string, tag: string): string | undefined {
  return str(text.match(new RegExp(`<${tag}>([^<]*)</${tag}>`))?.[1])
}

/** The STS error code and message: JSON as requested, or the service's native XML envelope. */
export function awsError(res: ProbeResponse): { code?: string; message?: string } {
  const b = body(res)
  if (isPlainObject(b.Error)) return { code: str(b.Error.Code), message: str(b.Error.Message) }
  return { code: xmlTag(res.text, 'Code'), message: xmlTag(res.text, 'Message') }
}

/** STS reports a signing time outside its 5-minute window with these words. */
const CLOCK_SKEW = /signature expired|not yet current/i

export function parseCallerIdentity(res: ProbeResponse): ProbeResult {
  if (res.status === 200) {
    const envelope = body(res).GetCallerIdentityResponse
    const result = isPlainObject(envelope) && isPlainObject(envelope.GetCallerIdentityResult)
      ? envelope.GetCallerIdentityResult
      : undefined
    const arn = str(result?.Arn) ?? xmlTag(res.text, 'Arn')
    if (!arn) return shapeError(res)
    return validResult({ account: { label: hideEmails(arn) } })
  }

  // Fixed texts for the credential errors: AWS's own wording is generic, and a
  // signature mismatch may quote the canonical request, session token included.
  const { code, message } = awsError(res)
  const opts = { httpStatus: res.status, providerCode: code }
  switch (code) {
    case 'AccessDenied':
      // AWS verifies the signature before it evaluates any policy.
      return validResult({ notes: ['AWS accepted the key, but a policy denies GetCallerIdentity, so the identity is not shown'] })
    case 'InvalidClientTokenId':
      return errorResult('invalid_key', 'AWS does not recognise this access key ID (or its session token)', opts)
    case 'SignatureDoesNotMatch':
      return CLOCK_SKEW.test(message ?? '')
        ? errorResult('unexpected_response', "AWS rejected the signing time: this server's clock is more than 5 minutes off, so the key was not judged", opts)
        : errorResult('invalid_key', 'the secret access key does not match this access key ID', opts)
    case 'ExpiredToken':
      return errorResult('invalid_key', 'the session token has expired', opts)
    case 'IncompleteSignature':
    case 'ValidationError':
      return errorResult('unexpected_response', message ?? code, opts)
    case 'Throttling':
      return errorResult('rate_limited', message ?? 'Rate exceeded', opts)
  }
  if (message) return errorResult(kindForStatus(res.status), message, opts)
  return statusError(res)
}

/**
 * GetCallerIdentity with the one retry the catalogue calls for. A signature
 * mismatch has a single cause a second try can cure, a stale signing time, so
 * the retry is re-signed at the current time (the AWS SDKs retry a clock-skew
 * error once, too). A second mismatch is the secret, or a clock that really is
 * off, which parseCallerIdentity tells apart.
 */
export async function stsGetCallerIdentity(
  http: ProbeHttp,
  creds: AwsCredentials,
  region: string | undefined,
  now: Date,
): Promise<ProbeResult> {
  if (region !== undefined && !isValidAwsRegion(region)) return errorResult('unexpected_response', INVALID_REGION_MESSAGE)
  let res = await http(stsRequest(creds, region, now))
  if (res.status !== 200 && awsError(res).code === 'SignatureDoesNotMatch') {
    res = await http(stsRequest(creds, region, new Date()))
  }
  return parseCallerIdentity(res)
}

export const awsProbe: ProbeDef = {
  id: 'aws',
  service: 'aws',
  label: 'AWS',
  group: 'sources',
  field: 'trufflehogAwsAccessKeyId',
  companions: [
    { field: 'trufflehogAwsSecretKey', required: true },
    { field: 'trufflehogAwsSessionToken', required: false },
  ],
  reportLoneCompanion: true,
  kind: 'validity',
  costNote: 'Free: GetCallerIdentity needs no permission and is not billed',
  docsUrl: 'https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html',
  dashboardUrl: 'https://console.aws.amazon.com/iam/home#/security_credentials',
  verifiedOn: null,
  endpoint: 'POST sts.amazonaws.com/ (GetCallerIdentity)',
  run: async ctx => {
    const secretKey = ctx.companions.trufflehogAwsSecretKey ?? ''
    if (!ctx.key || !secretKey) {
      return notCheckedResult('companion_missing', 'AWS needs both the access key ID and the secret access key')
    }
    const sessionToken = ctx.companions.trufflehogAwsSessionToken || undefined
    return stsGetCallerIdentity(ctx.http, { accessKeyId: ctx.key, secretKey, sessionToken }, undefined, ctx.now)
  },
}
